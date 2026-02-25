const http = require("http");
const express = require("express");
const crypto = require("crypto");
const app = express();
const assets = require("./assets.json");

app.use(express.static("public"));

const serverPort = process.env.PORT || 3000;
const server = http.createServer(app);
const WebSocket = require("ws");

const TOKEN_TTL = 300;

let keepAliveId;

const wss =
  process.env.NODE_ENV === "production"
    ? new WebSocket.Server({ server })
    : new WebSocket.Server({ port: 5001 });

server.listen(serverPort);
console.log(
  `Server started on port ${serverPort} in stage ${process.env.NODE_ENV}`
);

function verifyAuth(message) {
  try {
    const data = JSON.parse(message);
    if (data.type !== "auth") return false;

    const { token, timestamp } = data;
    const age = Math.floor(Date.now() / 1000) - Number(timestamp);

    if (age > TOKEN_TTL || age < 0) return false;

    const expected = crypto
      .createHmac("sha256", WS_SECRET)
      .update(String(timestamp))
      .digest("hex");

    return crypto.timingSafeEqual(
      Buffer.from(token, "hex"),
      Buffer.from(expected, "hex")
    );
  } catch {
    return false;
  }
}

wss.on("connection", function (ws, req) {
  console.log("Connection Opened");
  console.log("Client size: ", wss.clients.size);

  ws.authenticated = false;

  if (wss.clients.size === 1) {
    console.log("first connection. starting keepalive");
    keepServerAlive();
  }

  ws.on("message", (data) => {
    let stringifiedData = data.toString();

    if (stringifiedData === "pong") {
      console.log("keepAlive");
      return;
    }

    if (!ws.authenticated) {
      if (verifyAuth(stringifiedData)) {
        ws.authenticated = true;
        ws.send(JSON.stringify({ type: "auth_ok" }));
        ws.send(JSON.stringify({ type: "opt", options: assets }));
        console.log("Client authenticated");
      } else {
        ws.send(JSON.stringify({ type: "auth_fail" }));
        console.log("Client auth failed, closing");
        ws.close();
      }
      return;
    }

    try {
      const d = { type: "td", data: JSON.parse(data) };
      broadcast(ws, JSON.stringify(d), false);
    } catch (err) {
      console.log(`Failed to send: ${err}`);
    }
  });

  ws.on("close", (data) => {
    console.log("closing connection");

    if (wss.clients.size === 0) {
      console.log("last client disconnected, stopping keepAlive interval");
      clearInterval(keepAliveId);
    }
  });
});

const broadcast = (ws, message, includeSelf) => {
  if (includeSelf) {
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  } else {
    wss.clients.forEach((client) => {
      if (client !== ws && client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    });
  }
};

const keepServerAlive = () => {
  keepAliveId = setInterval(() => {
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send("ping");
      }
    });
  }, 50000);
};

app.get("/", (req, res) => {
  res.send("Hello World!");
});