const express=require("express"),session=require("express-session"),bcrypt=require("bcryptjs"),nodemailer=require("nodemailer"),{Pool}=require("pg"),crypto=require("crypto"),path=require("path");

const app=express(),PORT=process.env.PORT||3000;

const pool=process.env.DATABASE_URL
?new Pool({
    connectionString:process.env.DATABASE_URL,
    ssl:process.env.DATABASE_URL.includes("localhost")
      ?false
      :{rejectUnauthorized:false}
  })
:null;

const mailer=process.env.SMTP_HOST
?nodemailer.createTransport({
    host:process.env.SMTP_HOST,
    port:+(process.env.SMTP_PORT||587),
    secure:String(process.env.SMTP_SECURE||"false")==="true",
    auth:{
      user:process.env.SMTP_USER,
      pass:process.env.SMTP_PASS
    }
  })
:null;

app.use(express.json());
app.use(express.urlencoded({extended:true}));

app.use(session({
  secret:process.env.SESSION_SECRET||"CHANGE_THIS",
  resave:false,
  saveUninitialized:false,
  cookie:{
    maxAge:6048e5,
    httpOnly:true,
    sameSite:"lax"
  }
}));

app.use(express.static(path.join(__dirname,"public")));

const db=(q,p=[])=>{
  if(!pool) throw Error("DATABASE_URL is not configured.");
  return pool.query(q,p);
};

async function init(){

  if(!pool) return;

  await db(`
    CREATE TABLE IF NOT EXISTS users(
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
    );

    CREATE TABLE IF NOT EXISTS transactions(
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      type VARCHAR(30),
      amount_cents INTEGER,
      description TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS withdrawals(
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      amount_cents INTEGER,
      method VARCHAR(30),
      details TEXT,
      status VARCHAR(20) DEFAULT 'PENDING',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);
}

const auth=(q,s,n)=>
  q.session.userId
    ?n()
    :s.status(401).json({error:"Please sign in."});

const tok=()=>crypto.randomBytes(32).toString("hex");


app.get("/api/health",(q,s)=>
  s.json({
    ok:true,
    version:"2.0"
  })
);


app.post("/api/register",async(q,s)=>{

  try{

    let u=String(q.body.username||"").trim();
    let e=String(q.body.email||"").trim().toLowerCase();
    let p=String(q.body.password||"");

    if(!u||!e||!p)
      return s.status(400).json({
        error:"All fields are required."
      });

    if(p.length<6)
      return s.status(400).json({
        error:"Password must be at least 6 characters."
      });

    let t=tok();

    let h=await bcrypt.hash(p,10);

    let c=crypto
      .randomBytes(5)
      .toString("hex")
      .toUpperCase();

    await db(
      "INSERT INTO users(username,email,password_hash,referral_code,verification_token,verification_expires) VALUES($1,$2,$3,$4,$5,NOW()+INTERVAL '24 hours')",
      [u,e,h,c,t]
    );

    if(mailer){

      let base=
        process.env.APP_URL||
        `https://${process.env.RENDER_EXTERNAL_HOSTNAME}`;

      let url=
        `${base}/verify.html?token=${t}`;

      await mailer.sendMail({
        from:
          process.env.SMTP_FROM||
          process.env.SMTP_USER,
        to:e,
        subject:"Verify your GameEarn email",
        html:
          `<h2>Welcome to GameEarn</h2>
           <p><a href="${url}">Verify your email</a></p>
           <p>This link expires in 24 hours.</p>`
      });
    }

    s.json({
      ok:true,
      message:
        mailer
        ?"Account created. Check your email to verify it."
        :"Account created, but SMTP email delivery is not configured yet."
    });

  }catch(e){

    console.error(e);

    s.status(
      e.code==="23505"
      ?409
      :500
    ).json({
      error:
        e.code==="23505"
        ?"Username or email already exists."
        :"Registration failed."
    });
  }
});


app.get("/api/verify",async(q,s)=>{

  try{

    let r=await db(
      "UPDATE users SET email_verified=TRUE,verification_token=NULL,verification_expires=NULL WHERE verification_token=$1 AND verification_expires>NOW() RETURNING id",
      [String(q.query.token||"")]
    );

    if(!r.rowCount)
      return s.status(400).json({
        error:"Invalid or expired verification link."
      });

    s.json({
      ok:true,
      message:"Email verified. You can now sign in."
    });

  }catch(e){

    s.status(500).json({
      error:"Verification failed."
    });
  }
});


app.post("/api/resend-verification",async(q,s)=>{

  try{

    let e=
      String(q.body.email||"")
      .trim()
      .toLowerCase();

    let r=await db(
      "SELECT id,email,email_verified FROM users WHERE email=$1",
      [e]
    );

    if(!r.rowCount||r.rows[0].email_verified)
      return s.json({
        ok:true,
        message:"If needed, a verification email was sent."
      });

    if(!mailer)
      return s.status(503).json({
        error:"Email delivery is not configured yet."
      });

    let t=tok();

    await db(
      "UPDATE users SET verification_token=$1,verification_expires=NOW()+INTERVAL '24 hours' WHERE id=$2",
      [t,r.rows[0].id]
    );

    let base=
      process.env.APP_URL||
      `https://${process.env.RENDER_EXTERNAL_HOSTNAME}`;

    let url=
      `${base}/verify.html?token=${t}`;

    await mailer.sendMail({
      from:
        process.env.SMTP_FROM||
        process.env.SMTP_USER,
      to:e,
      subject:"Verify your GameEarn email",
      html:
        `<p><a href="${url}">Verify your GameEarn email</a></p>`
    });

    s.json({
      ok:true,
      message:"Verification email sent."
    });

  }catch(e){

    s.status(500).json({
      error:"Could not resend verification email."
    });
  }
});


app.post("/api/login",async(q,s)=>{

  try{

    let e=
      String(q.body.email||"")
      .trim()
      .toLowerCase();

    let r=await db(
      "SELECT * FROM users WHERE email=$1",
      [e]
    );

    if(
      !r.rowCount||
      !(await bcrypt.compare(
        q.body.password,
        r.rows[0].password_hash
      ))
    )
      return s.status(401).json({
        error:"Invalid email or password."
      });

    if(!r.rows[0].email_verified)
      return s.status(403).json({
        error:"Please verify your email before signing in."
      });

    q.session.userId=
      r.rows[0].id;

    s.json({
      ok:true
    });

  }catch(e){

    s.status(500).json({
      error:"Login failed."
    });
  }
});


app.post("/api/logout",(q,s)=>
  q.session.destroy(()=>
    s.json({ok:true})
  )
);


app.get(
  "/api/me",
  (q,s,n)=>auth(q,s,n),
  async(q,s)=>{

    let r=await db(
      "SELECT id,username,email,balance_cents,referral_code FROM users WHERE id=$1",
      [q.session.userId]
    );

    s.json({
      user:r.rows[0]
    });
  }
);


const offers={
  game1:["Reach Level 5","Games",96],
  game2:["Complete starter mission","Games",250],
  survey1:["Take a short survey","Surveys",75],
  app1:["Try a new app","Apps",180]
};


app.get(
  "/api/offers",
  (q,s,n)=>auth(q,s,n),
  (q,s)=>
    s.json({
      offers:
        Object.entries(offers)
        .map(([id,x])=>({
          id,
          title:x[0],
          category:x[1],
          reward_cents:x[2]
        }))
    })
);


app.post(
  "/api/offers/:id/complete",
  (q,s,n)=>auth(q,s,n),
  async(q,s)=>{

    let o=offers[q.params.id];

    if(!o)
      return s.status(404).json({
        error:"Offer not found."
      });

    try{

      await db(
        "UPDATE users SET balance_cents=balance_cents+$1 WHERE id=$2",
        [o[2],q.session.userId]
      );

      await db(
        "INSERT INTO transactions(user_id,type,amount_cents,description) VALUES($1,'OFFER',$2,$3)",
        [q.session.userId,o[2],o[0]]
      );

      s.json({
        ok:true,
        reward_cents:o[2]
      });

    }catch(e){

      s.status(500).json({
        error:"Could not credit reward."
      });
    }
  }
);


app.get(
  "/api/transactions",
  (q,s,n)=>auth(q,s,n),
  async(q,s)=>
    s.json({
      transactions:
        (
          await db(
            "SELECT * FROM transactions WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50",
            [q.session.userId]
          )
        ).rows
    })
);


/* =========================================
   WITHDRAWAL
   ========================================= */

app.post(
  "/api/withdraw",
  (q,s,n)=>auth(q,s,n),
  async(q,s)=>{

    try{

      let a=
        Math.round(
          +q.body.amount_cents
        );

      let m=
        String(
          q.body.method||""
        );

      let d=
        String(
          q.body.details||""
        ).trim();


      /*
       * STEAM ACCOUNT = $1 MINIMUM
       *
       * UPI = $10 MINIMUM
       * PAYPAL = $10 MINIMUM
       * GIFT CARD = $10 MINIMUM
       */

      const minimumCents =
        m==="game_reward"
          ?100
          :1000;


      if(
        !Number.isInteger(a)||
        a<minimumCents
      ){

        return s.status(400).json({
          error:
            `Minimum withdrawal for ${
              m==="game_reward"
                ?"Steam Account"
                :"this payout method"
            } is $${(
              minimumCents/100
            ).toFixed(2)}.`
        });
      }


      if(
        ![
          "paypal",
          "upi",
          "gift_card",
          "game_reward"
        ].includes(m)
      ){

        return s.status(400).json({
          error:"Invalid method."
        });
      }


      let u=
        await db(
          "SELECT balance_cents FROM users WHERE id=$1",
          [q.session.userId]
        );


      if(
        !u.rowCount||
        u.rows[0].balance_cents<a
      ){

        return s.status(400).json({
          error:"Insufficient balance."
        });
      }


      await db(
        "UPDATE users SET balance_cents=balance_cents-$1 WHERE id=$2",
        [a,q.session.userId]
      );


      let w=
        await db(
          "INSERT INTO withdrawals(user_id,amount_cents,method,details) VALUES($1,$2,$3,$4) RETURNING id,status",
          [
            q.session.userId,
            a,
            m,
            d
          ]
        );


      await db(
        "INSERT INTO transactions(user_id,type,amount_cents,description) VALUES($1,'WITHDRAWAL',$2,$3)",
        [
          q.session.userId,
          -a,
          `Withdrawal #${w.rows[0].id}`
        ]
      );


      s.json({
        ok:true,
        withdrawal:
          w.rows[0]
      });


    }catch(e){

      console.error(
        "WITHDRAW ERROR:",
        e
      );

      s.status(500).json({
        error:"Withdrawal request failed."
      });
    }
  }
);


app.get(
  "*",
  (q,s)=>
    s.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    )
);


init()
  .then(()=>
    app.listen(
      PORT,
      ()=>
        console.log(
          "GameEarn v2 running on "+PORT
        )
    )
  )
  .catch(e=>{
    console.error(e);
    process.exit(1);
  });
