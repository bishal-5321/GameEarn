const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// =========================================================
// DATABASE
// =========================================================

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DATABASE_URL.includes("localhost")
        ? false
        : { rejectUnauthorized: false }
    })
  : null;

// =========================================================
// MIDDLEWARE
// =========================================================

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

// =========================================================
// DATABASE HELPER
// =========================================================

const db = (query, params = []) => {
  if (!pool) {
    throw new Error("DATABASE_URL is not configured.");
  }

  return pool.query(query, params);
};

// =========================================================
// DATABASE INITIALIZATION + MIGRATION
// =========================================================

async function init() {
  if (!pool) {
    throw new Error("DATABASE_URL is not configured.");
  }

  // USERS
  await db(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(40) UNIQUE NOT NULL,
      email VARCHAR(160) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      balance_cents INTEGER DEFAULT 0,
      referral_code VARCHAR(20) UNIQUE NOT NULL,
      email_verified BOOLEAN DEFAULT TRUE,
      verification_token TEXT,
      verification_expires TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Add missing columns to old databases
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
    ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT TRUE
  `);

  await db(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW()
  `);

  // Make existing accounts usable without verification
  await db(`
    UPDATE users
    SET email_verified = TRUE
    WHERE email_verified IS NULL OR email_verified = FALSE
  `);

  // TRANSACTIONS
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

  // WITHDRAWALS
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

  console.log("Database initialization completed.");
}

// =========================================================
// AUTH
// =========================================================

const auth = (req, res, next) => {
  if (req.session.userId) {
    return next();
  }

  return res.status(401).json({
    error: "Please sign in."
  });
};

// =========================================================
// HEALTH CHECK
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
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

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

    const passwordHash = await bcrypt.hash(password, 10);

    const referralCode = require("crypto")
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
        email_verified
      )
      VALUES (
        $1,
        $2,
        $3,
        $4,
        TRUE
      )
      `,
      [
        username,
        email,
        passwordHash,
        referralCode
      ]
    );

    res.json({
      ok: true,
      message: "Account created successfully."
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
// LOGIN
// =========================================================

app.post("/api/login", async (req, res) => {
  try {
    const email = String(req.body.email || "")
      .trim()
      .toLowerCase();

    const password = String(req.body.password || "");

    const result = await db(
      `
      SELECT *
      FROM users
      WHERE email = $1
      `,
      [email]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const user = result.rows[0];

    const passwordCorrect = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordCorrect) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    req.session.userId = user.id;

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

app.get("/api/me", auth, async (req, res) => {
  try {
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

    if (!result.rowCount) {
      return res.status(404).json({
        error: "User not found."
      });
    }

    res.json({
      user: result.rows[0]
    });

  } catch (error) {
    console.error("ME ERROR:", error);

    res.status(500).json({
      error: "Could not load account."
    });
  }
});

// =========================================================
// OFFERS
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

// =========================================================
// GET OFFERS
// =========================================================

app.get("/api/offers", auth, (req, res) => {
  res.json({
    offers: Object.entries(offers).map(
      ([id, data]) => ({
        id,
        title: data[0],
        category: data[1],
        reward_cents: data[2]
      })
    )
  });
});

// =========================================================
// COMPLETE OFFER
// =========================================================

app.post(
  "/api/offers/:id/complete",
  auth,
  async (req, res) => {
    const offer = offers[req.params.id];

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
      console.error("OFFER ERROR:", error);

      res.status(500).json({
        error: "Could not credit reward."
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
    try {
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

    } catch (error) {
      console.error(
        "TRANSACTIONS ERROR:",
        error
      );

      res.status(500).json({
        error: "Could not load transactions."
      });
    }
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
        Number(req.body.amount_cents)
      );

      const method = String(
        req.body.method || ""
      );

      const details = String(
        req.body.details || ""
      ).trim();

      // Minimum withdrawal = $1
      if (
        !Number.isInteger(amount) ||
        amount < 100
      ) {
        return res.status(400).json({
          error: "Minimum withdrawal is $1.00."
        });
      }

      const allowedMethods = [
        "paypal",
        "upi",
        "gift_card",
        "game_reward"
      ];

      if (!allowedMethods.includes(method)) {
        return res.status(400).json({
          error: "Invalid withdrawal method."
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

      if (!user.rowCount) {
        return res.status(404).json({
          error: "User not found."
        });
      }

      if (
        user.rows[0].balance_cents <
        amount
      ) {
        return res.status(400).json({
          error: "Insufficient balance."
        });
      }

      // Remove balance
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

      // Create withdrawal
      const withdrawal = await db(
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

      // Transaction record
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
        withdrawal: withdrawal.rows[0]
      });

    } catch (error) {
      console.error(
        "WITHDRAW ERROR:",
        error
      );

      res.status(500).json({
        error: "Withdrawal request failed."
      });
    }
  }
);

// =========================================================
// FRONTEND
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
// START
// =========================================================

init()
  .then(() => {
    app.listen(PORT, () => {
      console.log(
        "GameEarn v2 running on port " + PORT
      );
    });
  })
  .catch((error) => {
    console.error(
      "DATABASE INITIALIZATION ERROR:",
      error
    );

    process.exit(1);
  });
