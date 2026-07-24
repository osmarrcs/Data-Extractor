import app from "./app";

const rawPort = process.env["PORT"] || "10000";
const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

app.listen(port, '0.0.0.0', () => {
  console.log(`API rodando em 0.0.0.0:${port}`);
});
