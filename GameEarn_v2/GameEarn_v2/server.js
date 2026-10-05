const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DATABASE_URL.includes("localhost")
        ? false
        : { rejectUnauthorized: false }
    })
  : null;

const mailer = process.env.SMTP_HOST
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: +(process.env.SMTP_PORT || 587),
      secure: String(process.env.SMTP_SECURE || "false") === "true",
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    })
  : null;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "CHANGE_THIS",
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 6048e5,
      httpOnly: true,
      sameSite: "lax"
    }
  })
);

app.use(express.static(path.join(__dirname, "public")));

const db = (query, params = []) => {
  if (!pool) {
    throw new Error("DATABASE_URL is not configured.");
  }

  return pool.query(query, params);
};

async function init() {
  if (!pool) return;

  // =========================================================
  // USERS TABLE
  // =========================================================

  await db(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(40) UNIQUE NOT NULL,
      email VARCHAR(160) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      balance_cents INTEGER DEFAULT 0,
      referral_code VARCHAR(20) UNIQUE NOT NULL,
      email_verified BOOLEAN DEFAULT FALSE,
      verification_token TEXT,
      verification_expires TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // =========================================================
  // TRANSACTIONS TABLE
  // =========================================================

  await db(`
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      type VARCHAR(30),
      amount_cents INTEGER,
      description TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // =========================================================
  // WITHDRAWALS TABLE
  // =========================================================

  await db(`
    CREATE TABLE IF NOT EXISTS withdrawals (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      amount_cents INTEGER,
      method VARCHAR(30),
      details TEXT,
      status VARCHAR(20) DEFAULT 'PENDING',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // =========================================================
  // DATABASE MIGRATION
  //
  // This fixes older GameEarn databases.
  // CREATE TABLE IF NOT EXISTS does NOT add missing columns
  // to a table that already exists.
  // =========================================================

  await db(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS balance_cents INTEGER DEFAULT 0
  `);

  await db(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS referral_code VARCHAR(20)
  `);

  await db(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE
  `);

  await db(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS verification_token TEXT
  `);

  await db(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS verification_expires TIMESTAMPTZ
  `);

  await db(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()
  `);

  await db(`
    ALTER TABLE transactions
    ADD COLUMN IF NOT EXISTS user_id INTEGER
  `);

  await db(`
    ALTER TABLE transactions
    ADD COLUMN IF NOT EXISTS type VARCHAR(30)
  `);

  await db(`
    ALTER TABLE transactions
    ADD COLUMN IF NOT EXISTS amount_cents INTEGER
  `);

  await db(`
    ALTER TABLE transactions
    ADD COLUMN IF NOT EXISTS description TEXT
  `);

  await db(`
    ALTER TABLE transactions
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()
  `);

  await db(`
    ALTER TABLE withdrawals
    ADD COLUMN IF NOT EXISTS user_id INTEGER
  `);

  await db(`
    ALTER TABLE withdrawals
    ADD COLUMN IF NOT EXISTS amount_cents INTEGER
  `);

  await db(`
    ALTER TABLE withdrawals
    ADD COLUMN IF NOT EXISTS method VARCHAR(30)
  `);

  await db(`
    ALTER TABLE withdrawals
    ADD COLUMN IF NOT EXISTS details TEXT
  `);

  await db(`
    ALTER TABLE withdrawals
    ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'PENDING'
  `);

  await db(`
    ALTER TABLE withdrawals
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()
  `);

  console.log("Database initialization/migration completed.");
}

const auth = (req, res, next) => {
  if (req.session.userId) {
    return next();
  }

  return res.status(401).json({
    error: "Please sign in."
  });
};

const tok = () => crypto.randomBytes(32).toString("hex");

// =========================================================
// HEALTH
// =========================================================

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    version: "2.0"
  });
});

// =========================================================
// REGISTER
// =========================================================

app.post("/api/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!username || !email || !password) {
      return res.status(400).json({
        error: "All fields are required."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must be at least 6 characters."
      });
    }

    const token = tok();

    const passwordHash = await bcrypt.hash(password, 10);

    const referralCode = crypto
      .randomBytes(5)
      .toString("hex")
      .toUpperCase();

    await db(
      `
      INSERT INTO users (
        username,
        email,
        password_hash,
        referral_code,
        verification_token,
        verification_expires
      )
      VALUES (
        $1,
        $2,
        $3,
        $4,
        $5,
        NOW() + INTERVAL '24 hours'
      )
      `,
      [
        username,
        email,
        passwordHash,
        referralCode,
        token
      ]
    );

    // =====================================================
    // EMAIL VERIFICATION
    // =====================================================

    if (mailer) {
      const base =
        process.env.APP_URL ||
        `https://${process.env.RENDER_EXTERNAL_HOSTNAME}`;

      const verifyUrl =
        `${base}/verify.html?token=${token}`;

      await mailer.sendMail({
        from:
          process.env.SMTP_FROM ||
          process.env.SMTP_USER,

        to: email,

        subject: "Verify your GameEarn email",

        html: `
          <h2>Welcome to GameEarn</h2>

          <p>
            Thanks for creating your GameEarn account.
          </p>

          <p>
            Click the button below to verify your email:
          </p>

          <p>
            <a href="${verifyUrl}"
               style="
                 display:inline-block;
                 padding:12px 20px;
                 background:#6c5ce7;
                 color:white;
                 text-decoration:none;
                 border-radius:8px;
               ">
              Verify Email
            </a>
          </p>

          <p>
            This verification link expires in 24 hours.
          </p>
        `
      });

      return res.json({
        ok: true,
        message:
          "Account created. Check your email to verify it."
      });
    }

    return res.json({
      ok: true,
      message:
        "Account created, but SMTP email delivery is not configured yet."
    });

  } catch (error) {
    console.error("REGISTRATION ERROR:", error);

    if (error.code === "23505") {
      return res.status(409).json({
        error: "Username or email already exists."
      });
    }

    return res.status(500).json({
      error: "Registration failed."
    });
  }
});

// =========================================================
// VERIFY EMAIL
// =========================================================

app.get("/api/verify", async (req, res) => {
  try {
    const token = String(req.query.token || "");

    const result = await db(
      `
      UPDATE users

      SET
        email_verified = TRUE,
        verification_token = NULL,
        verification_expires = NULL

      WHERE
        verification_token = $1
        AND verification_expires > NOW()

      RETURNING id
      `,
      [token]
    );

    if (!result.rowCount) {
      return res.status(400).json({
        error: "Invalid or expired verification link."
      });
    }

    res.json({
      ok: true,
      message: "Email verified. You can now sign in."
    });

  } catch (error) {
    console.error("VERIFICATION ERROR:", error);

    res.status(500).json({
      error: "Verification failed."
    });
  }
});

// =========================================================
// RESEND VERIFICATION
// =========================================================

app.post("/api/resend-verification", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const result = await db(
      `
      SELECT
        id,
        email,
        email_verified

      FROM users

      WHERE email = $1
      `,
      [email]
    );

    if (
      !result.rowCount ||
      result.rows[0].email_verified
    ) {
      return res.json({
        ok: true,
        message:
          "If needed, a verification email was sent."
      });
    }

    if (!mailer) {
      return res.status(503).json({
        error:
          "Email delivery is not configured yet."
      });
    }

    const token = tok();

    await db(
      `
      UPDATE users

      SET
        verification_token = $1,
        verification_expires =
          NOW() + INTERVAL '24 hours'

      WHERE id = $2
      `,
      [
        token,
        result.rows[0].id
      ]
    );

    const base =
      process.env.APP_URL ||
      `https://${process.env.RENDER_EXTERNAL_HOSTNAME}`;

    const verifyUrl =
      `${base}/verify.html?token=${token}`;

    await mailer.sendMail({
      from:
        process.env.SMTP_FROM ||
        process.env.SMTP_USER,

      to: email,

      subject: "Verify your GameEarn email",

      html: `
        <p>
          Click below to verify your GameEarn email:
        </p>

        <p>
          <a href="${verifyUrl}">
            Verify your GameEarn email
          </a>
        </p>
      `
    });

    res.json({
      ok: true,
      message: "Verification email sent."
    });

  } catch (error) {
    console.error(
      "RESEND VERIFICATION ERROR:",
      error
    );

    res.status(500).json({
      error:
        "Could not resend verification email."
    });
  }
});

// =========================================================
// LOGIN
// =========================================================

app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(
      req.body.password || ""
    );

    const result = await db(
      `
      SELECT *
      FROM users
      WHERE email = $1
      `,
      [email]
    );

    if (
      !result.rowCount ||
      !(await bcrypt.compare(
        password,
        result.rows[0].password_hash
      ))
    ) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    if (!result.rows[0].email_verified) {
      return res.status(403).json({
        error:
          "Please verify your email before signing in."
      });
    }

    req.session.userId =
      result.rows[0].id;

    res.json({
      ok: true
    });

  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      error: "Login failed."
    });
  }
});

// =========================================================
// LOGOUT
// =========================================================

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({
      ok: true
    });
  });
});

// =========================================================
// CURRENT USER
// =========================================================

app.get(
  "/api/me",
  auth,
  async (req, res) => {
    const result = await db(
      `
      SELECT
        id,
        username,
        email,
        balance_cents,
        referral_code

      FROM users

      WHERE id = $1
      `,
      [req.session.userId]
    );

    res.json({
      user: result.rows[0]
    });
  }
);

// =========================================================
// DEMO OFFERS
// =========================================================

const offers = {
  game1: [
    "Reach Level 5",
    "Games",
    96
  ],

  game2: [
    "Complete starter mission",
    "Games",
    250
  ],

  survey1: [
    "Take a short survey",
    "Surveys",
    75
  ],

  app1: [
    "Try a new app",
    "Apps",
    180
  ]
};

app.get(
  "/api/offers",
  auth,
  (req, res) => {
    res.json({
      offers:
        Object.entries(offers).map(
          ([id, data]) => ({
            id,
            title: data[0],
            category: data[1],
            reward_cents: data[2]
          })
        )
    });
  }
);

// =========================================================
// COMPLETE DEMO OFFER
// =========================================================

app.post(
  "/api/offers/:id/complete",
  auth,
  async (req, res) => {
    const offer =
      offers[req.params.id];

    if (!offer) {
      return res.status(404).json({
        error: "Offer not found."
      });
    }

    try {
      await db(
        `
        UPDATE users

        SET balance_cents =
          balance_cents + $1

        WHERE id = $2
        `,
        [
          offer[2],
          req.session.userId
        ]
      );

      await db(
        `
        INSERT INTO transactions (
          user_id,
          type,
          amount_cents,
          description
        )

        VALUES (
          $1,
          'OFFER',
          $2,
          $3
        )
        `,
        [
          req.session.userId,
          offer[2],
          offer[0]
        ]
      );

      res.json({
        ok: true,
        reward_cents: offer[2]
      });

    } catch (error) {
      console.error(
        "OFFER ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Could not credit reward."
      });
    }
  }
);

// =========================================================
// TRANSACTIONS
// =========================================================

app.get(
  "/api/transactions",
  auth,
  async (req, res) => {
    const result = await db(
      `
      SELECT *

      FROM transactions

      WHERE user_id = $1

      ORDER BY created_at DESC

      LIMIT 50
      `,
      [req.session.userId]
    );

    res.json({
      transactions: result.rows
    });
  }
);

// =========================================================
// WITHDRAW
// =========================================================

app.post(
  "/api/withdraw",
  auth,
  async (req, res) => {
    try {
      const amount = Math.round(
        +req.body.amount_cents
      );

      const method =
        String(req.body.method || "");

      const details =
        String(
          req.body.details || ""
        ).trim();

      if (
        !Number.isInteger(amount) ||
        amount < 100
      ) {
        return res.status(400).json({
          error:
            "Minimum withdrawal is $1.00."
        });
      }

      if (
        ![
          "paypal",
          "upi",
          "gift_card",
          "game_reward"
        ].includes(method)
      ) {
        return res.status(400).json({
          error: "Invalid method."
        });
      }

      const user = await db(
        `
        SELECT balance_cents

        FROM users

        WHERE id = $1
        `,
        [req.session.userId]
      );

      if (
        !user.rowCount ||
        user.rows[0].balance_cents <
          amount
      ) {
        return res.status(400).json({
          error:
            "Insufficient balance."
        });
      }

      await db(
        `
        UPDATE users

        SET balance_cents =
          balance_cents - $1

        WHERE id = $2
        `,
        [
          amount,
          req.session.userId
        ]
      );

      const withdrawal =
        await db(
          `
          INSERT INTO withdrawals (
            user_id,
            amount_cents,
            method,
            details
          )

          VALUES (
            $1,
            $2,
            $3,
            $4
          )

          RETURNING id, status
          `,
          [
            req.session.userId,
            amount,
            method,
            details
          ]
        );

      await db(
        `
        INSERT INTO transactions (
          user_id,
          type,
          amount_cents,
          description
        )

        VALUES (
          $1,
          'WITHDRAWAL',
          $2,
          $3
        )
        `,
        [
          req.session.userId,
          -amount,
          `Withdrawal #${withdrawal.rows[0].id}`
        ]
      );

      res.json({
        ok: true,
        withdrawal:
          withdrawal.rows[0]
      });

    } catch (error) {
      console.error(
        "WITHDRAW ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Withdrawal request failed."
      });
    }
  }
);

// =========================================================
// FRONTEND FALLBACK
// =========================================================

app.get("*", (req, res) => {
  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );
});

// =========================================================
// START SERVER
// =========================================================

init()
  .then(() => {
    app.listen(PORT, () => {
      console.log(
        "GameEarn v2 running on " + PORT
      );
    });
  })
  .catch(error => {
    console.error(
      "DATABASE INITIALIZATION ERROR:",
      error
    );

    process.exit(1);
  });
