require("dotenv").config();
const express = require("express");

const app = express();

const jwt = require("jsonwebtoken");
const posts = [
  {
    username: "Bharat",
    post: 1,
  },
  {
    username: "Om",
    post: 1,
  },
];

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStats(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

const generateAccessToken = (user) => {
  const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "15s",
  });

  return accessToken;
};

const refreshTokensMap = [];

app.get("/posts", authenticateToken, (req, res) => {
  res.json(posts.filter((post) => post.username === req.user.name));
});

app.post("/login", (req, res) => {
  const username = "Bharat";
  const user = { name: username };

  const accessToken = generateAccessToken(user);
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
  refreshTokensMap.push(refreshToken);
  res.json({ accessToken, refreshToken });
});

app.post("/token", (req, res) => {
  const refreshToken = req.headers.refreshtoken;
  if (!refreshToken) return res.sendStatus(401);
  if (!refreshTokensMap.includes(refreshToken)) return res.sendStatus(403);
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ name: user.name });
    res.send(accessToken);
  });
});

app.delete("/logout", (req, res) => {
  refreshTokensMap = refreshTokensMap.filter(
    (token) => token != req.header.token
  );
  res.sendStatus(204);
});

app.listen(3001, () => {
  console.log("running on 3001");
});
