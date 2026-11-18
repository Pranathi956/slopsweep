// demo file for slopsweep
const express = require("express");
const app = express();
const token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

app.get("/", (req, res) => {
  console.log("here");
  document.body.innerHTML = req.query.q;
  try { risky(); } catch (e) {}
  // rest of the implementation here
  res.send(eval(req.query.code));
});

// FIXME: add auth
app.listen(3000);
