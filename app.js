const { Router } = require("express");
const ethers = require("ethers");
const TronWeb = require("tronweb");
const mongoose = require("mongoose");
const queries = require("./database/queriesFunc");
const config = require("./config");
const hdWallet = require("tron-wallet-hd");
const ecc = require("tiny-secp256k1");
const { BIP32Factory } = require("bip32");
var axios = require("axios");

const bip39 = require("bip39");
const bitcoin = require("bitcoinjs-lib");
const HDKey = require("hdkey");
const CoinKey = require("coinkey");
const SLIP77 = require("slip77");

const app = Router();

// mainnet
var btcMain = require("./controllers/Bitcoin/index");
var ethMain = require("./controllers/Ethereum/eth");
var erc20Main = require("./controllers/Ethereum/erc20");
var apiServices = require("./database/services");

// testnet
var ethTest = require("./controllers/Testnet_Ethereum/eth");
var erc20Test = require("./controllers/Testnet_Ethereum/erc20");

// fantom
var fantomMainnet = require("./controllers/Fantom/eth");
var fantomERC20Mainnet = require("./controllers/Fantom/erc20");

// polygon
var polygonMainnet = require("./controllers/Polygon/eth");
var polygonERC20Mainnet = require("./controllers/Polygon/erc20");

// BSC
var bscMainnet = require("./controllers/BSC/eth");
var bscERC20Mainnet = require("./controllers/BSC/erc20");

// BSC
var avalancheMainnet = require("./controllers/Avalanche/eth");
var avalancheERC20Mainnet = require("./controllers/Avalanche/erc20");

// BSC
var cronosMainnet = require("./controllers/Cronos/eth");
var cronosERC20Mainnet = require("./controllers/Cronos/erc20");

app.use("/services", ensureWebToken, apiServices);

// mainnet server
app.use("/bitcoin/mainnet", ensureWebToken, btcMain);
app.use("/ether/mainnet", ensureWebToken, ethMain);
app.use("/token/mainnet", ensureWebToken, erc20Main);

// testnet
app.use("/ether/testnet", ensureWebToken, ethTest);
app.use("/token/testnet", ensureWebToken, erc20Test);

// Fantom Mainet
app.use("/fantom/mainnet", ensureWebToken, fantomMainnet);
app.use("/fantomToken/mainnet", ensureWebToken, fantomERC20Mainnet);

// Polygon Mainet
app.use("/polygon/mainnet", ensureWebToken, polygonMainnet);
app.use("/polygonToken/mainnet", ensureWebToken, polygonERC20Mainnet);

// BSC Mainet
app.use("/bsc/mainnet", ensureWebToken, bscMainnet);
app.use("/bscToken/mainnet", ensureWebToken, bscERC20Mainnet);

// Avalanche Mainet
app.use("/avalanche/mainnet", ensureWebToken, avalancheMainnet);
app.use("/avalancheToken/mainnet", ensureWebToken, avalancheERC20Mainnet);

// Cronos Mainet
app.use("/cronos/mainnet", ensureWebToken, cronosMainnet);
app.use("/cronosToken/mainnet", ensureWebToken, cronosERC20Mainnet);

app.post("/eth-to-usdt", async (req, res) => {
  try {
    // Ethereum network provider
    const ethProvider = new ethers.providers.JsonRpcProvider(
      "https://ethereum.publicnode.com"
    );

    // Uniswap v2 router contract address
    const uniswapRouterAddress = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";
    const pancakeRouterAddress = "0x10ED43C718714eb63d5aA57B78B54704E256024E";
    const maticUniswapRouterAddress =
      "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45";

    // Uniswap v2 router contract ABI
    const uniswapRouterAbi = [
      "function getAmountsOut(uint amountIn, address[] memory path) public view returns (uint[] memory amounts)",
      "function getAmountsIn(uint amountOut, address[] memory path) public view returns (uint[] memory amounts)",
      "function swapExactETHForTokens(uint amountOutMin, address[] calldata path, address to, uint deadline) external payable returns (uint[] memory amounts)",
      "function swapExactTokensForETH(uint amountOut, uint amountInMax, address[] calldata path, address to, uint deadline) external returns (uint[] memory amounts)",
    ];

    const erc20ABI = [
      "function balanceOf(address) view returns (uint256)",
      "function transfer(address to, uint amount)",
      "function transferFrom(address from, address to, uint amount)",
      "function approve(address spender, uint amount) returns (bool)",
      "function allowance(address owner, address spender) view returns (uint256)",
      "event Transfer(address indexed from, address indexed to, uint amount)",
      "event Approval(address indexed owner, address indexed spender, uint amount)",
    ];

    // USDT and WETH token addresses
    const usdtAddress = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
    const wethAddress = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
    // Token addresses for BNB and BUSD on the Binance Smart Chain network
    const bnbAddress = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c";
    const busdAddress = "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56";
    // Token addresses for USDT and Matic on the Polygon network
    const maticUsdtAddress = "0xc2132D05D31c914a87C6611C10748AEb04B58e8F";
    const maticAddress = "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270";
    const { ETH_AMOUNT, PRIVATE_KEY } = req.body;

    console.log(1);
    // const wallet = new ethers.Wallet(PRIVATE_KEY, ethProvider);

    // Uniswap router contract instance
    const uniswapRouter = new ethers.Contract(
      uniswapRouterAddress,
      uniswapRouterAbi,
      ethProvider
    );

    console.log(2);
    // Convert ETH_AMOUNT to wei
    const ethAmountWei = ethers.utils.parseEther(ETH_AMOUNT.toString());

    // Get the estimated amount of USDT that will be received from swapping ETH_AMOUNT ETH
    const amountsOut = await uniswapRouter.getAmountsOut(
      ethAmountWei.toString(),
      [wethAddress, usdtAddress]
    );
    console.log(amountsOut.toString());
    const usdtAmount = amountsOut[1].toString();
    // Sign and send the transaction to swap ETH for USDT
    const wallet = new ethers.Wallet(PRIVATE_KEY, ethProvider);
    const uniswapRouterWithSigner = uniswapRouter.connect(wallet);
    const deadline = Math.floor(Date.now() / 1000) + 1200; // 20 minutes from now
    const tx = await uniswapRouterWithSigner.swapExactETHForTokens(
      usdtAmount,
      [wethAddress, usdtAddress],
      wallet.address,
      deadline,
      {
        gasPrice: ethers.utils.parseUnits("30", "gwei"),
        value: ethAmountWei,
        gasLimit: 200000,
      }
    );
    res.json({ txHash: tx.hash });
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
});

// Swap USDT to ETH
app.post("/usdt-to-eth", async (req, res) => {
  try {
    // Ethereum network provider
    const ethProvider = new ethers.providers.JsonRpcProvider(
      "https://ethereum.publicnode.com"
    );

    // Uniswap v2 router contract address
    const uniswapRouterAddress = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D";
    const pancakeRouterAddress = "0x10ED43C718714eb63d5aA57B78B54704E256024E";
    // const maticUniswapRouterAddress =
    //   "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45";

    // Uniswap v2 router contract ABI
    const uniswapRouterAbi = [
      "function getAmountsOut(uint amountIn, address[] memory path) public view returns (uint[] memory amounts)",
      "function getAmountsIn(uint amountOut, address[] memory path) public view returns (uint[] memory amounts)",
      "function swapExactETHForTokens(uint amountOutMin, address[] calldata path, address to, uint deadline) external payable returns (uint[] memory amounts)",
      "function swapExactTokensForETH(uint amountOut, uint amountInMax, address[] calldata path, address to, uint deadline) external returns (uint[] memory amounts)",
    ];

    const erc20ABI = [
      "function balanceOf(address) view returns (uint256)",
      "function transfer(address to, uint amount)",
      "function transferFrom(address from, address to, uint amount)",
      "function approve(address spender, uint amount) returns (bool)",
      "function allowance(address owner, address spender) view returns (uint256)",
      "event Transfer(address indexed from, address indexed to, uint amount)",
      "event Approval(address indexed owner, address indexed spender, uint amount)",
    ];

    // USDT and WETH token addresses
    const usdtAddress = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
    const wethAddress = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
    // Token addresses for BNB and BUSD on the Binance Smart Chain network
    const bnbAddress = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c";
    const busdAddress = "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56";
    // Token addresses for USDT and Matic on the Polygon network
    // const maticUsdtAddress = "0xc2132D05D31c914a87C6611C10748AEb04B58e8F";
    // const maticAddress = "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270";

    // Uniswap router contract instance
    const uniswapRouter = new ethers.Contract(
      uniswapRouterAddress,
      uniswapRouterAbi,
      ethProvider
    );
    // PancakeSwap router contract instance

    const { USDT_AMOUNT, PRIVATE_KEY } = req.body;

    // Convert USDT_AMOUNT to wei
    const usdtAmountWei = ethers.utils.parseUnits(USDT_AMOUNT.toString());
    // Get the estimated amount of ETH that will be received from swapping USDT_AMOUNT USDT
    const amountsOut = await uniswapRouter.getAmountsOut(
      usdtAmountWei.toString(),
      [usdtAddress, wethAddress]
    );

    const ethAmount = amountsOut[1].toString();

    // Sign and send the transaction to swap USDT for ETH
    const wallet = new ethers.Wallet(PRIVATE_KEY, ethProvider);
    const usdtContract = new ethers.Contract(usdtAddress, erc20ABI, wallet);

    const uniswapRouterWithSigner = uniswapRouter.connect(wallet);

    const approvalTx = await usdtContract.approve(
      uniswapRouterAddress,
      usdtAmountWei,
      {
        gasLimit: 100000,
        gasPrice: ethers.utils.parseUnits("30", "gwei"),
      }
    );
    await approvalTx.wait();

    const deadline = Math.floor(Date.now() / 1000) + 1200; // 20 minutes from now
    const tx = await uniswapRouterWithSigner.swapExactTokensForETH(
      usdtAmountWei.toString(),
      ethAmount.toString(),
      [usdtAddress, wethAddress],
      wallet.address,
      deadline,
      {
        gasPrice: ethers.parseUnits("30", "gwei"),
        gasLimit: 200000,
      }
    );
    res.json({ txHash: tx.hash, approvalTx: approvalTx.hash });
  } catch (err) {
    res.status(500).json({ msg: err.message });
  }
});

app.get("/create-mnemonics-wallet-eth", (req, res) => {
  try {
    console.log("ddd", req.query.numWallet);
    const mnemonic1 = ethers.utils.entropyToMnemonic(
      ethers.utils.randomBytes(16)
    );

    const mnemonic = mnemonic1;
    let walletList = [];

    // the number of wallets to create
    const numWallets = req.query.numWallet;

    // create a HDNode instance from the mnemonic
    const hdNode = ethers.utils.HDNode.fromMnemonic(mnemonic);

    // derive wallets from the HDNode instance
    for (let i = 0; i < numWallets; i++) {
      const path = `m/44'/60'/0'/0/${i}`;
      const wallet = new ethers.Wallet(hdNode.derivePath(path).privateKey);
      walletList.push({
        walletAddress: wallet.address,
        walletPrivateKey: wallet.privateKey,
      });
      console.log(
        `Wallet ${i}: Address: ${wallet.address}, Private key: ${wallet.privateKey}`
      );
    }
    res.status(200).send({
      message: "Wallet get successfully",
      mnemonics: mnemonic,
      wallet: walletList,
    });
  } catch (e) {
    res.status(400).send({
      code: 400,
      message: `Address creating stops with the error. ${e}`,
    });
  }
});

// Get Address From Mnemonics
app.get("/get-eth-wallet-from-mnemonics", async function (req, res) {
  try {
    // const HttpProvider = TronWeb.providers.HttpProvider;
    // const fullNode = new HttpProvider("https://api.trongrid.io");
    // // const fullNode = new HttpProvider("http://192.168.1.162:8090");
    // const solidityNode = new HttpProvider("https://api.trongrid.io");
    // const eventServer = new HttpProvider("https://api.trongrid.io");
    // const tronWeb = new TronWeb(fullNode,solidityNode,eventServer);
    // console.log(fullNode);

    // // create new account
    // const account = tronWeb.createRandom({
    //   "mnemonic": {
    //     "phrase": "chimney cloth deny claim play rude love dose apart shove rack stone",
    //     "path": "m/44'/195'/0'/0/0",
    //     "locale": "en"
    //   },
    //   "privateKey": "0x79092289f3bfde55f079202e3642b2c4ba071d5f0b85d65b1919c8724e94848c",
    //   "publicKey": "0x0421c47d627bc2d856760dda17b42b726b4bc8f5def76aed0cbcd71566d0ffedfc3904c9c854854a5019b8373d2aed0c6b96ff5f3be07722403088742b0949a6c9",
    //   "address": "TEFAyPnainfiAJBuhExfMLJeHHxD2DZJmF",
    // });
    // console.log(account);
    // res.status(200).send({message: "Mnemonics are correct!", account: account});
    // return;
    let walletList = [];

    const mnemonic = req.body.mnemonics;
    // console.log(mnemonic);
    // res.status(200).send({message: "Mnemonics are correct!"});
    const hdNode = ethers.utils.HDNode.fromMnemonic(mnemonic);
    let i = 0;
    const path = `m/44'/60'/0'/0/${i}`;
    const wallet = new ethers.Wallet(hdNode.derivePath(path).privateKey);
    walletList.push({
      walletAddress: wallet.address,
      walletPrivateKey: wallet.privateKey,
    });
    res.status(200).send({
      message: "Mnemonics are correct!",
      mnemonics: mnemonic,
      wallet: walletList,
    });
  } catch (e) {
    res.status(400).send({
      code: 400,
      message: `Address could not be fetched, error: ${e}`,
    });
  }
});

app.get("/get-tron-wallet-from-mnemonics", async function (request, response) {
  const utils = hdWallet.utils;
  const seed = request.body.mnemonics;
  const isValidSeed = utils.validateMnemonic(seed);
  if (isValidSeed) {
    const accounts = await utils.generateAccountsWithMnemonic(seed, 2);
    response.status(200).send({
      message: "Mnemonics are correct!",
      mnemonics: seed,
      wallet: accounts,
    });
  } else {
    response
      .status(500)
      .send({ message: "Invalid Mnemonics", mnemonics: seed });
  }
});
app.get("/get-btc-wallet-transactions", async function (req, res) {
  const bitcoinAddress = req.body.address;

  const apiUrl = `https://chain.api.btc.com/v3/address/${bitcoinAddress}/tx`;
  axios(apiUrl)
    .then((response) => {
      const details = response.data;
      res.status(200).send({
        result: details,
      });
    })
    .catch((e) => {
      res.status(400).send({
        code: 400,
        message: `Address could not be fetched, error: ${e}`,
      });
    });
});
app.get("/get-btc-wallet-balance", async function (req, res) {
  const bitcoinAddress = req.body.address;

  const apiUrl = `https://chain.api.btc.com/v3/address/${bitcoinAddress}`;
  axios(apiUrl)
    .then((response) => {
      const details = response.data;
      res.status(200).send({
        result: details,
      });
    })
    .catch((e) => {
      res.status(400).send({
        code: 400,
        message: `Address could not be fetched, error: ${e}`,
      });
    });
});
app.get("/get-btc-wallet-unspent", async function (req, res) {
  const bitcoinAddress = req.body.address;

  const apiUrl = `https://chain.api.btc.com/v3/address/${bitcoinAddress}/unspent`;

  axios(apiUrl)
    .then((response) => {
      const details = response.data;
      res.status(200).send({
        result: details,
      });
    })
    .catch((e) => {
      res.status(400).send({
        code: 400,
        message: `Address could not be fetched, error: ${e}`,
      });
    });
});
// Get Address From Mnemonics
app.get("/get-btc-wallet-from-mnemonics", async function (req, res) {
  try {
    const mnemonic = req.body.mnemonics;
    const bip32 = BIP32Factory(ecc);
    const seed = bip39.mnemonicToSeedSync(mnemonic);
    const network = bitcoin.networks.bitcoin;
    const root = bip32.fromSeed(seed, network);
    const path = "m/84'/0'/0'/0/0";
    const account = root.derivePath(path);

    const { address } = bitcoin.payments.p2wpkh({
      pubkey: account.publicKey,
      network,
    });
    const coinKey = new CoinKey(account.privateKey, bitcoin.networks.bitcoin);
    const info = {
      walletAddress: address, // Bitcoin public address
      path, // BIP84 path
      walletPrivateKey: coinKey.privateKey.toString("hex"), // Private key in hexadecimal
      WIF: coinKey.privateWif, // Wallet Import Format (WIF) private key
    };
    res.status(200).send({
      message: "Mnemonics are correct!",
      mnemonics: mnemonic,
      wallet: info,
    });
  } catch (e) {
    res.status(400).send({
      code: 400,
      message: `Address could not be fetched, error: ${e}`,
    });
  }
});

app.post("/tron-to-usdt", async function (request, response) {
  const { private_key, trx_amount, sender } = request.body;
  if (!private_key || !trx_amount || !sender) {
    response.status(400).send({
      message: "Invalid Request Data",
    });
  }
  var tronWeb = new TronWeb({
    fullHost: "https://api.trongrid.io",
    headers: { "TRON-PRO-API-KEY": "47bef6e6-d498-4501-a216-f13a90cb5371" },
    privateKey: private_key,
  });
  let contract = await tronWeb
    .contract()
    .at("TKzxdSv2FZKQrEqkKVgp5DcwEXBEKMg2Ax");
  const currentTime = Math.floor(Date.now() / 1000);
  const deadline = currentTime + 20 * 60;
  try {
    const swap = await contract.methods
      .swapExactETHForTokens(
        1,
        [
          "TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR",
          "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
        ],
        sender,
        deadline
      )
      .send({
        feeLimit: 100000000,
        callValue: tronWeb.toSun(trx_amount),
      });
    response.status(200).send({
      hash: swap,
      message: "You swap is under process",
    });
  } catch (e) {
    response.status(400).send({
      message: "There was an error",
      error: e,
    });
  }
});

app.post("/usdt-to-tron", async function (request, response) {
  const { private_key, usdt_amount, sender } = request.body;
  if (!private_key || !usdt_amount || !sender) {
    response.status(400).send({
      message: "Invalid Request Data",
    });
  }
  var tronWeb = new TronWeb({
    fullHost: "https://api.trongrid.io",
    headers: { "TRON-PRO-API-KEY": "47bef6e6-d498-4501-a216-f13a90cb5371" },
    privateKey: private_key,
  });
  const usdtContract = await tronWeb
    .contract()
    .at("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");
  let contract = await tronWeb
    .contract()
    .at("TKzxdSv2FZKQrEqkKVgp5DcwEXBEKMg2Ax");
  const currentTime = Math.floor(Date.now() / 1000);
  const deadline = currentTime + 20 * 60;
  try {
    const approvalTx = await usdtContract
      .approve("TKzxdSv2FZKQrEqkKVgp5DcwEXBEKMg2Ax", usdt_amount)
      .send({
        feeLimit: 100000000,
      });
    console.log(approvalTx);
    const swap = await contract.methods
      .swapExactTokensForETH(
        usdt_amount,
        1,
        [
          "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
          "TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR",
        ],
        sender,
        deadline
      )
      .send({
        feeLimit: 100000000,
      });
    response.status(200).send({
      hash: swap,
      message: "You swap is under process",
    });
  } catch (e) {
    response.status(400).send({
      message: "There was an error",
      error: e,
    });
  }
});
// app.get("/tron-to-usdt", async function (request, response) {
//   var tronWeb = new TronWeb({
//     fullHost: "https://api.trongrid.io",
//     headers: { "TRON-PRO-API-KEY": "47bef6e6-d498-4501-a216-f13a90cb5371" },
//     privateKey: request.query.private_key,
//   });
//   // "397A265DECBBA67B3A8A21DF0F475FCDF6C4DCF38E3EC62451DC8C2CF92EEB14",
//   console.log(tronWeb, "tronWeb");
//   let contract = await tronWeb
//     .contract()
//     .at("TKzxdSv2FZKQrEqkKVgp5DcwEXBEKMg2Ax");

//   // const usdt = await contract.methods
//   //   .getExchange("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")
//   //   .call();
//   // console.log(contract, 'usdt');
//   //     return;
//   // 100000000
//   try {
//     const swap = await contract
//       .swapExactETHForTokens(
//         1000000,
//         [
//           "TYsbWxNnyTgsZaTFaue9hqpxkU3Fkco94a",
//           "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
//         ],
//         "TDNy8T5RXUePAmiLQQCgYWND9cWytaP3a2",
//         1662825600
//       )
//       .send();
//     console.log(swap, "swap");
//     response.status(200).send({
//       hash: swap,
//       message: "You swap is under process",
//     });
//   } catch (e) {
//     console.log(e, "s");
//     response.status(400).send({
//       message: "There was an error",
//       error: e,
//     });
//   }
// });

app.get("/create-tron-wallet", async function (request, response) {
  const utils = hdWallet.utils;
  const seed = utils.generateMnemonic();
  const isValidSeed = utils.validateMnemonic(seed);
  const accounts = await utils.generateAccountsWithMnemonic(seed, 2);
  response.status(200).send({
    message: "Mnemonics are correct!",
    mnemonics: seed,
    wallet: accounts[0],
  });
});

app.get("/", async function (request, response) {
  response.contentType("application/json");
  response.end(JSON.stringify("Node is running"));
});

app.use("/*", function (req, res) {
  return res.json({
    code: 404,
    data: null,
    msg: "Invalid Request 1 {URL Not Found}",
  });
});

async function ensureWebToken(req, res, next) {
  if (req.path !== "/createApi") {
    const x_access_token = req.headers["authorization"];
    if (typeof x_access_token !== undefined) {
      const query = await queries.checkApiExist(x_access_token);
      if (query[0] != x_access_token && query.toString() != "") {
        next();
      } else {
        res.sendStatus(403);
      }
    } else {
      res.sendStatus(403);
    }
  } else {
    const admin_key = config.admin.auth_key;
    const admin_password = config.admin.auth_password;

    const auth_key = req.body["auth_key"];
    const auth_password = req.body["auth_password"];
    if (admin_key == auth_key && admin_password == auth_password) next();
    else res.sendStatus(403);
  }
}

module.exports.routes = app;
