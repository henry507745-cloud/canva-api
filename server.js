const express = require('express');
const cors = require('cors');

const app = express();

app.use(cors());
app.use(express.json());

app.get('/', (req, res) => {
  res.send('API 運作正常');
});

app.get('/api/games', (req, res) => {
  res.json([
    { id: 1, name: '遊戲 A' },
    { id: 2, name: '遊戲 B' }
  ]);
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`API listening on ${port}`);
});
