import express from "express";
import * as http from "http";
import bcrypt from "bcrypt";
import Fingerprint from 'express-fingerprint';
import * as FingerprintParams from "express-fingerprint/lib/parameters";
import requestIp from "request-ip";
import cookieParser from "cookie-parser";

import { getUser, hasUser, setUser, updateUser } from "./users";

const SALT_ROUNDS = 10;
const NONCE_TOKEN_BORDER = 1000 * 60 * 2;
const COOKIE_NONCE_TOKEN_KEY = 'nonceToken';
const port = process.env.PORT;
const app = express();

const server = http.createServer(app);

app.use(cookieParser());
app.use(express.json());
app.use(requestIp.mw());
app.use(Fingerprint({
  parameters:[
    FingerprintParams.useragent,
    FingerprintParams.acceptHeaders,
    async (_next, _req, _res) => {
      const next: any = _next;
      const req: any = _req;
      const res: any = _res;

      let cid = req.cookies.cid;

      if (!req.cookies.cid) {
        const cid = await bcrypt.genSalt(SALT_ROUNDS);
        res.cookie('cid', cid);
      }

      next(null, { cid });
    },
  ],
}));

const clearNonceToken = async (res: express.Response, hash: string) => {
  res.clearCookie(COOKIE_NONCE_TOKEN_KEY);
  try {
    await updateUser(hash, { nonce: null });
  } catch (error) {
    // pass
  }
};

const checkAccess = async (req: express.Request, res: express.Response) => {
  const { hash } = req.fingerprint ?? { hash: "" };
  const nonceToken = req.cookies.nonceToken;
  const user = await hasUser(hash) ? await getUser(hash) : null;
  let error: null | string = null;

  if (!hash) {
    error = "Hash doesn't exist";
  } else if (!Boolean(nonceToken)) {
    error = "Nonce token doesn't exist";
  } else if (!Boolean(user) || !user?.nonce?.token) {
    error = "User doesn't exist";
  } else if (nonceToken !== user?.nonce?.token) {
    error = "Nonce is incorrect";
  } else if (new Date().getTime() > user.nonce.created + NONCE_TOKEN_BORDER) {
    error = "Nonce is old";
  }

  if (error) {
    await clearNonceToken(res, hash);
    throw new Error(error);
  }
};

app.get("/api/check-access", async (req, res) => {
  try {
    await checkAccess(req, res);
    res.status(200);
  } catch (error) {
    res.status(401);
  }
  res.end();
});

app.post("/api/sign-in", async (req, res) => {
  const { hash } = req.fingerprint ?? { hash: "" };
  const { password }: { password: string } = req.body;

  if (hash) {
    if (await hasUser(hash)) {
      const user = await getUser(hash);

      if (await bcrypt.compare(password, user.password)) {
        const token = await bcrypt.genSalt(SALT_ROUNDS);

        updateUser(hash, {
          nonce: { token, created: new Date().getTime() },
        });
        res.cookie(COOKIE_NONCE_TOKEN_KEY, token);
        res.status(200);
      } else {
        await clearNonceToken(res, hash);
        res.statusMessage = "Credential is incorrect";
        res.status(401);
      }
    } else {
      const salt = await bcrypt.genSalt(SALT_ROUNDS);
      const token = await bcrypt.genSalt(SALT_ROUNDS);

      setUser(hash, {
        password: await bcrypt.hash(password, salt),
        nonce: { token, created: new Date().getTime() },
      });
      res.cookie(COOKIE_NONCE_TOKEN_KEY, token);
      res.status(200);
    }
  } else {
    res.status(400);
  }

  res.end();
});

app.get("*", (_, res) => {
  res.send("Server app");
  res.end();
});

server.listen(port, () => {
  console.log(`http://localhost:${port}`);
});
