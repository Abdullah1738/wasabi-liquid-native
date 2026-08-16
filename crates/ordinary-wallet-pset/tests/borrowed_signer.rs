#[allow(dead_code)]
mod common;

use elements::bitcoin::PublicKey as BitcoinPublicKey;
use elements::confidential::{Asset, AssetBlindingFactor, Nonce, Value, ValueBlindingFactor};
use elements::encode::{deserialize, serialize};
use elements::secp256k1_zkp::{All, Message, PublicKey, Secp256k1, SecretKey, ecdsa};
use elements::sighash::{SighashCache, SighashRangeproofMode};
use elements::{
    Address, AddressParams, AssetId, EcdsaSighashType, LockTime, OutPoint, Script, Transaction,
    TxOut, TxOutSecrets, Txid,
};
use miniscript::bitcoin::NetworkKind;
use miniscript::bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use rand::SeedableRng;
use rand::rngs::StdRng;
use sha2::{Digest, Sha256};
use wasabi_liquid_native_ordinary_pset::{
    ExplicitFee, FinalizedOrdinaryTransaction, OrdinaryP2wpkhSigner, OrdinarySigningError,
};
use wasabi_liquid_native_ordinary_wallet_pset::{
    OrdinaryWalletTransactionFailure, OrdinaryWalletTransactionReason,
    build_blinded_ordinary_wallet_pset, build_sign_and_finalize_ordinary_wallet_transaction,
};
use wasabi_liquid_native_wallet_facts::{
    BorrowedOrdinaryP2wpkhSigner, BorrowedOrdinarySpendKey, DescriptorCatalog, DescriptorNetwork,
};

use common::{planned_outputs, selected_batch, synthetic_material};

const ORDINARY_SIGHASH_TYPE: EcdsaSighashType = EcdsaSighashType::AllPlusRangeproof;

/// The deterministic txid produced by the one-key borrowed-signer fixture.
const EXPECTED_ONE_KEY_TXID: &str =
    "6f86ae233e61e7cbe62dbaf2e7b0cbd56c9ab9d5d542ccb75945cd4364c5a1ed";
/// The deterministic wtxid produced by the one-key borrowed-signer fixture.
const EXPECTED_ONE_KEY_WTXID: &str =
    "d5ecd2d951dd7a77884f0ee0c9852f6c75a2529a7b329bb7514c3c07d667651f";
/// The deterministic broadcast serialization of the one-key fixture.
const EXPECTED_ONE_KEY_BROADCAST_HEX: &str = concat!(
    "02000000010252a144da51936d4bfe4d122a4af9f6f962b872bb7f7b084deba3ad7b4979",
    "aefc0100000000ffffffff52a144da51936d4bfe4d122a4af9f6f962b872bb7f7b084deb",
    "a3ad7b4979aefc0000000000ffffffff030a95eaa7fe97f29cf7fb3da5d101ec804b57da",
    "cfeddb457044eb2b9f2a302065f109810fec400c3336f1a8e2a8cc29bb70ea6419b3ee9c",
    "9d4a7528f3f8635bf77b2b03e1612157186b70e06dcaf0a0bbddc38007a15366293a176c",
    "c6c3283ec383d08c160014a3e18f06b5369914234bd7df7462d7bbd36357140b8a9f5b8d",
    "1d65b923bbef9d5aa1284e647d01542d9031b8bfc7b37c015447a6d409bf8829c5744870",
    "9a21195590b6ff6fc5789b8cedaa98d0019b608b00c64b5215024b0e169b1d70abe15093",
    "f688e1284473e1db68abbd0290832c97e994db83f13a160014d363d538bea12647f61c63",
    "4bdd7a791d676850e901499a818545f6bae39fc03b637f2a4e1e64e590cac1bc3a6f6d71",
    "aa4443654c1401000000000000006400000000000000000247304402204a76cdca143595",
    "229d6445c7e246352536e3e8bec3fbb6e48657f4cc7ff4e992022075424f616f44fd1b69",
    "ea4e837a39c620d01e62ef7e69d16de1ea0b5766327cf74121020b29fe631d09073f9e0b",
    "36fde03c0442591a1cba0858c1fe4591bb2e1e926ed200000002483045022100ff074945",
    "123fd37ae281da7e1f8fd9854e087596635e8691bdabe1dbf8ae40c702203134a475df51",
    "b2898d9af89d667f9d5f14db28ac122d746099aa585ea39b19cb4121020b29fe631d0907",
    "3f9e0b36fde03c0442591a1cba0858c1fe4591bb2e1e926ed20063020003362018b8d61f",
    "86f04a1a0def425601fad3d58a9420f1c4d59705ae8a94a153d5844a13e3715b7049ac90",
    "a0adfa90cc51c1a7c06b72b64a54ae540e534cd9552b1b68afd41d51d05b357dfba97faf",
    "f3800d5aaf293acfec9998de77efa4cea7a2fd4e10603300000000000000019cd3a200a5",
    "95ea12be4f71d95f1941af314321979b63654e3f8d79e2e0ba7be06382eb393be0a35eaf",
    "fabc56ca1c8cc2a68c629047593038d88d82b69f2b23f191a157ab83ccacefb6481702fc",
    "7f37381fc012a0c4801ab7c3d1a4ed5e4b5349d28bf3d26f76fdf826fae55975e0fecdc0",
    "9e41ad579b49b223c2475fad0b79ce9ebcb5857866e0a7d8bbd9bbbd6f15149af49f1476",
    "a5f11a6273ff291cefbdb17ca0fbdf6a221aa4ab8da5d6799765a9b3f0f86531c79de28d",
    "fed80484d72c6350b73725a0c36af0691c141a8cfa73fe5f86ae291f0b6eaff402399332",
    "cfc58cff1d5bf7d73795bf202064cdab767b361f3368c82f1b4236e2b1149213f600e105",
    "aa3dc870535fb38d2029670a8aa8c7ec567c5dc52e45b24167dc4a94e655e49ce7453d90",
    "bda511b46417f5671f66af156462b7692750b4486c17a7596cbebf942811e68cbe24b672",
    "54106e1c174ec5f330d37c6a1b1880a763e7ff50f60355872b4ef1428740e1af16e192b6",
    "561765af4ee77957c36b5db995cddd372ed4bacc04c0a209fca185013344e0207e14da7f",
    "d7c6664d2181dd7b5bc838b48c8d46661986e24bf2c6fef62db1b8b0b849048a9967b121",
    "ff087311ae2276358a92004fe9c4c7e239b01d503587551bfd979dc3ba30dd6dbedad2c9",
    "30aafdfd0f70ceb96f8e1df94aceacaaa5b00025aae6688c4978de2afe2c78cf6c18f072",
    "c1295334bd664d60f169568748eef7f106b25de381b6f4507e3648b6dd257bba07ce1805",
    "65f29f944b76be3034442c575ea43bacc67826faa9e8980af1da3e9b442b80daa71970e2",
    "26509cb518704e86cfe904855cd02caa3bedcbaab6d225aeb0ac85a8eada05f13cbf82b0",
    "998cfdb006ee63f6089cedf12b79aad883810fddbce7352687dc9e9934181604aa239154",
    "79a2a36eb6b019b61890e4302d58c91c3c672bf3477a6c7bd1b7e864fa416675be759d36",
    "93013c78e4fb02d2605b10494e3b847e3358ea72b4495e4dfdee8299a11c52fc11e20bab",
    "89081e606968f385bad9489a2cfd86638ab8c8cb4c76fa6642c70e30c113987881535c60",
    "9b6a7a62fa7671a7bffe6e8e6dab73b83039f6fd547f128717cb70b8e8f719dd4390da1d",
    "4ec94525c65452ca83c6192e736bf32502cb3a2b7c1183d368c40588a7f18a375b9ad2b3",
    "f7323d1f9551c41dfab49d8d5cdcadec9067d65d16a32d50135953a02e982129cdff0d05",
    "d9e83d4998f3cdcf60044820538233d28093546701811d5dd8902ac2f8f97c5899d0425f",
    "0d648b16386fea5ccc57be11036f28783be42cce42222dd845b7fe380b69e010f79e0969",
    "8caf1d063de41f785a32ad02fdb7752825a512c22576751f4046675cc471941a36de6401",
    "8751cdb6b6841b7a26f15d3057d3c79d10793b5b3c09577c21ffd92dfb8f9b706689201b",
    "0c032a46e12775e694af167ff5ba05d7dc5286e60001305b9d012ad5c0a9f4a2a17144de",
    "bab636006ab03e6be79c3fe7abe7bd789a6ee25bad3f47aa11d708d115efa8304e1d0b2e",
    "e6891a2dd154b33c695f378b95e49e0408fec9cc77e0a3a32d710703d9a3b064a4f6bd86",
    "d39160f533d2d6c486cd54973b334cb96dd72d84a6ef82b3ed927b389e41f94c46b3f0bf",
    "0d591e54757e2a996258eb1520739474be1984fde69412f507214abb72f5aeea1d2d011c",
    "8cd7f49dcd8a8ad1788724d5ddd3c346e28ed9e868c6dae1cfeb182138676bcfc96782ab",
    "41a48e07bd2df690e6aae91c5f1967c15f43a30e554b5919aebb840520634cbecef45173",
    "22bf23387bc120c76d9322e1cda60cbdff9f39f2babe810f06194a5d1c2115453bc00a87",
    "297fcfe58d28c83a30fb756a6187610be8a8d87c6947b554cb0e5e86fe7ed2f58fdd983b",
    "1d2a935afa607d834738b722f7ff01d8bc657b6f53628eac503c17bbdbe0d6762597ce04",
    "c60becc045f24867dcbf1daa65d3c9a795addfe012bf925b413b68694cd8811dbd470ba4",
    "0a7c9baa9dbfad1c4dadd3aa4606ff5bd416aedb355c410c1c6ca5d01b774dc9dcdaa83a",
    "9b4e79ee4537b84d8675816bfa55f86157a7174f913be92d6bfbfade7c866cd0e5df0844",
    "f555279e4e0a4820f431f150ec1b2c8665b7f22ce879e3ecd2569fe69c2790008b77bad3",
    "8f053a3b5a892f736088233d7adb2213062318bb9085f9f671a7877d5bb29c8ebe0bdec5",
    "94db3d292bf4a4c3c19f950d2e6900d6d820a1b800c45af8c46b4ba7249cb9725fd2dffb",
    "ba82c1bb1e74d5fba455f87f347357e4840b37f5004245222ba9a1f828b8ef179701299a",
    "0086edd911245645910a3834053089ef685f6ffa03bae257e86be161f56c8a2d4ec8e110",
    "fc49000739cbd4341c88d20da03b5c58c4f0b6b2615177aac03367fa89fcda3699d6d2fe",
    "e31103c8a09d923a5ebf382bd1ad057a6a660e8e1c670ec52f7fd0583aba1377a1c4d925",
    "86fe38b3f27a7e5918fb8abb9ba62499c74a98baa7fd658fe6946022bcccb48cb4c48b71",
    "a6b2b02a88d80b3ee234ba04d3c384a74b19d01df9ebcdaab52ede9ee1b97a9ee2960732",
    "7d66d155c81ba3b6ccfa575fe5df5d153d788eb6655019529149ad02d16c85b9019c8610",
    "f72e6dba3dcc8519d2814d891090a7b82fe530fe51d78fc3d7f8ab53bc219ccb2d3f8717",
    "10319a2492308414757dbbc6a9f021e4e3c7cf622a300419a125aae896be73559ff0b1ff",
    "eba4a845897a76907d38d8b3b855102312bee9b9e389142a940794b70cb3a3b6650556bf",
    "59b30cefcf5bac1fec6c9cdb5b5f04f76403559a7749949f93b7dc12c59c4dd71cddbb8e",
    "3dba2d8a99664b8ccabad5607a810e73cc816acc2f24ed5bd153067445048be8c5a84ca8",
    "da008006ca10f2d482150550e57e8975fecabd97c6046ac7a527f8c5531f94f5c1e3db2f",
    "5abdb35bd0ee737fa32dd8009e98a08146151ee04f0607151f05a6d9545a66dc6a5f5b58",
    "309333ad246f7c94a0703f9936b4f224bab9d747f4a286e7e41ec1d0aba28530ebd751d8",
    "a6de55a92d3872595947e718449f384a4bd06d0334593947961d3f4c45e454c6a903804e",
    "35c681a1eda928573e35dc0f2b6a5264e8b6d86109dfaea2d5356dbecf91c78907800307",
    "0dd72f589f99c9b4cf42f0fa81a528c04a2b7bb902a2f7b97ee1f6e3a2d9227758fbb4cb",
    "65714307a6a8c8c783675eef6aa4cb3dbeaf9cb7dbda2f2158205caf7e339a2b75ac540c",
    "3cadb258d708dac36f5293a6fece852ca78c227daec9e6b000d7e0eee0df66ebbae4c49c",
    "6c69c6364a118ed038599c7ee519ffe156796805f3d90c954107be30e88e748d1c403b9d",
    "63c6f4acad983559cd371392992733535447a6282a0cd33f02b00ada4b73357e08a89847",
    "dcfd2710b1fc5e6bc0ccd04e940e8b5785feb794c5fd3d5883b281643464753407931df7",
    "ca03573537a3f419b8fccf8e9aaa02963e8e97152fb228882100ece8584cdc41bd4c6d42",
    "817f04acb3af0c7165d37cb0f97c07f47bba320dbd713b803717b9f21f13427389a34580",
    "06e084b7134f07626bce3966c0db8a5a35a71fb52db78c3d7b0e80bb6a50319b1042f8b1",
    "85411d4a8034c698e71f8d18c877a04fa1785ca0c722b6fb50c9c6c097f55fd70f410fb4",
    "04704df4024708fb210063fc69f83188cfd99373007c96bb5bf39dbc3c4ded6c26b373c1",
    "a6990846ab4d18530040094c46f0cf3b44a212783dee538d1da8d5fa97f0a66e43c137f9",
    "7ff629b5acdb2ff863bef72d9f034acc977641dadc4ccabf4670d6f47ce7abbf95af2a0c",
    "65a334d3d39d59a1f74a6b6d74813ec897b5980467a3ff269f2c5f4bfdda2e863501f981",
    "6c7ac0215c4f7abb685c57e8dc7062b46a1d1f571709385612165a5debf66f1111d77977",
    "a2fab15e0591f0a99f86f2634b4c2fd69b3826773f163a36107cfe5ff96edcab24425fc2",
    "5ee99d0c54633516c67150d23b1fb06dced4be34c80412a0736e710854ed0f31605db7ea",
    "aa354f7e4a21cb726d31390594abc2ca88452be3e2608e5402fbf3bcb1cce9dc98c35f60",
    "9e6e25d260e6062aa9320e1de6a512bd37af80c02c894a3353daeb5898ae22a6fa4f0ec6",
    "0f964d10280bb57824806c1f7c1b223836a247aea727da432299eff9df9513004dce756c",
    "51a3ffe58bca5d7bc57b7f333216ff4678dbd6fbe76d86b121da889e8426fb6ddb8fa36c",
    "9fcac2f41f3ca1e121516fda32d9bd4392477406e346c6021f2395fd3249b888f787a9eb",
    "e8443e34bf43a4dcaa7bd0d54a79e34d55f19881e16cd3837f6293b5cad55ba05de52c5c",
    "af0cfaedc847432089a8bddb774da802d7e8bc0d8234cdc664bb5ec6d8e1b80a722dc117",
    "0ecbaae76fe4efb51a251569d4686f446dd15b7a489b00d5ed3afc20aefa03474ee960df",
    "c4635c62cf06407a338734c9905e1a1b01a143fa2cc2fe85cd03704afedc510011c581b1",
    "fb9eeece343acd1f93d23b7b9d6e181e34d526e120d7635ec34ed2fde71b2c26a4c918bb",
    "53b9df2131c689d746b8af1f551de7fd5929823a00f8e822dfc29d61413c1f78fb7a440c",
    "25a93af4f22d9c83e975cc8d9ebb90b350d158c19efce3b6f52be86e69a23b805d52454d",
    "2a84e5d84c3295ff4011b8f30f7ce7899d968404ccd33456e684c1ea88fb12e473396b63",
    "b7352ba8fa0d1b116366c3d12216ebacb37215e4ea20b600ff5472bdb3c3ef1a94eeabab",
    "4019691c08eeaeeadf4451ff414d9975d85aa614f5e69a6a214234b8d8ccf7ddfb226767",
    "97dc7a67b102e75149bdced9f25a85593de94af4d92fa19d4f57ec42cf38729d1992d853",
    "f1e4cc03c77eaf0fc29f63e4c07cb7751360a77c085233834562fe90cfae689dda93fc99",
    "c22dddaf705e4ead3a5b1043afa76551744d2ecddee9ba94dfbec3df115d5d800f7a8682",
    "7a31d68c32595dc8307dd6ef8f61ea863245821e2a5a21056d76831afb922acb6b232acd",
    "bb9c087895d6215ce8a87a6e3983328fa07bf03583a7b88c11eb1a8591c097446afdc084",
    "eea296b68e3c741b5a761b6a9908f54065da52000191336b84e3d1a99b2ab3fa7c149304",
    "ff8a268bf947c93540cdda4ae2fcf5322becb03f9104bc411525693c332d2e7347419321",
    "01858441e1fc709f4c424670807c970446eb0475d51d274f2be4567f1e26322d8b08821b",
    "3b3a7ce9fb701ebd4b313f9e052bb20b5322d72f3372ca8e2586f9db4229eb777bee72b6",
    "0da2e8da658a5fde182b28ea63116c29bd5eaa21d822d55acfd33aef624e06765c80c920",
    "17d234d5b600f93b65215593bcac3f7e2555e6fc01052912ff99b3d5c433d1106e903fe7",
    "a7c7323297c2196446e270bcdd28c95105b5fe10e660f6c9feb03bc74315939c3484d6c4",
    "09dcd1d631a0847e89f8c6871a64148ec0a9708509690ae4d926a055cdb01cd6fd8b40e2",
    "e60c7c18efcb5f934e5ba4a14953961e75b389938396d3494b91feb5b2db2c862fe54fd0",
    "310280ed9d12f23768db28609c3ba35a0b59ce9dd926ccf9cefe8ef54c231bcf54999c62",
    "cdee886e2ab3e05685f76d3b8065f9f3788322ce4cadeacaf7e561ffd26f5138d6f21375",
    "8fc28876a2753fa156f2c387b6e2ff796067b5ccff98c6a2de3a94cdfa193f3f0ec38107",
    "a3e3dadb97c92810dae7316dbb383135c9ea182b16208028ee796790c705cab932b1d977",
    "23b254c4c826caa729c18e4b5d23db88b1ce557f5d994bfbdf86da6d4b58c8f371deaaa0",
    "b271d778de534ba62f321b0ce738cca695787f5d3e3192602c66ff8bd375cb63778050da",
    "7fa073a04507d6c6aaa5ad10bd83bb66f441c1f2ce9782fa67148316aced4131c45b7bb2",
    "9bef8f5c4bb41a93e36dd17963731c68dece2b84a7b8c187b7923b01d582468f73b20b34",
    "210c13be90a06c043b3c7481cbfb01d0bcb32d630200031f338cd99fa24572a89b3df6ae",
    "f503687e4188f89cae2d74d1792487a0156ca0c403d9532c2a8e8e4db45c5a98c2662633",
    "904663788182f31708f832fc6c5a9c652962cede8270bdcf809f8eca07d70f9b436d33f4",
    "97a65e737453cdad969097fd4e10603300000000000000016f388c01179267d9486516c5",
    "ddde48014ba9eba4fcdee494487986f2ac0d63285f3e3025474a85dc6db003cf6d5ec62a",
    "b781969395d09e64a38226698d947446a8a6c738adff8d151d4ffd60bf8ded7288177fae",
    "1bc9460c6cd68014fa46896ee12ab0fc2471f579efdae79ca16fc0e60e130f99d5acfc32",
    "52aeb6db8f836dd39c1accc372fbeeb22d5a522088c41745f5398a247fba777602d445c8",
    "5ea9cd91fed504ba1e06c08e627cd53e7dd140eafa01ee366fbd768a9f68aab751e317f0",
    "7a905872d2b64a328805fa6d81dfc46964274b1476a3a9ac8ac13f63c5381da3039dc942",
    "704a3cda68262f8fa15f90ea862c0c56ce8d83d43a8183ba394ea6853026ac0b29e762ee",
    "eba78a10917adfdef94a651f7d33c7e33a6a0251d246ceb49659bf89807ab660bf933150",
    "f77c1334a9787bcb04f442e76c69c524b84e7b7fba5a9a69b3a3f6ee3b97a574024d1df0",
    "8029db9fdb89b6c5f4805b2bff040fd1daf9f4b3c75047dfb11e83d955184a9c97df4abd",
    "1b3e91d00e577507946daa2466ee50d6e1ede59e0a3a58e80d38b3d3678d976f3b6aaadc",
    "35258724e110da114f23b7998330e03f6e0e9a3c624984d03ac901a1d6276351468adc5d",
    "1cb83e56e58dfa0b337868a5873cd937d0c1a3b6211a10e8544c97dee021e5eaaf8a92af",
    "22a40f85eef60cc98ae727892f93dfa2bc71b2341c61fbe4eb24494d4a333f26be6f32af",
    "5aa425f2de6b55222e85ba4ee886d3abda65ea0ace6ed634c873ebb16d497683619b2cc7",
    "aefcc9eef80404b8e532c24c3863775843e50fcb1127f47c8450eb28b07c1488ddca369e",
    "d69005ead65a5747bf78c321ef90c7431a3e2119e4a18329c5ed3227d03bf22047e683c2",
    "556692c4eabe5b0c186594a3223413c5ad9b82a3f534d36efcab1be2dae71300042bb2c4",
    "c09eaa115aa1e833bd15e44569b0c3de4213b239055c0c1e814214d084798ec958f06cde",
    "928c023d91f9f88a13f6e54569a7155e48f1e57c52edb49d27b83593bbd7a43467bb26c0",
    "612cba2394f20465dfcf9dc583de3226b86a3a2cae058dd428409f0c8b9e2aa61a88762c",
    "e3b5874a8486c72c5823f8561be032e07a33171ebbea477957a005aef9628eb10784daef",
    "9288f47bbfcddfecf12a64d05832c62705f1f05b397fc5ee00d3b6d75b5c74382b9c3e76",
    "b897e7d2f93fc25a639e847423d5d8585f272b5eda2df27dd5a4a1e12a7866c499bfb4a9",
    "aa00dbbb9a0f793dcda3a539f6d804852f43f8870f092141a27685a60876a8c4abc9d26e",
    "466665d372f46f4319195705519222028583aabc6bc4b4edf9a2c117e15da7f506e32fad",
    "34dc14180f70f337c5a3e157df6391e4d3f20e514368832b301ad2ca908d562a6017b700",
    "a10985fc3fbcf46dae0e1ed623dbc17d55c650cdf4227aeae52a3418bac39ccfea36102d",
    "0c6d7d79b0de166877d22b05d0e6f5907efa8918e56050436c3d4d2281a4c53dd73eee40",
    "9eefb323ee107e005455d685717fac620baeaa7fb9241a5d3274bd72b84ed07770e3c296",
    "9be0ff2fe61d67d11300860d4da5251ae4a10b538e51ba3321cd61d341703281207447b8",
    "075b59773fd1b1906f6d20da745e5cb6b2a0b969a35f8709cc918fc37064a4646ef65fb4",
    "c22f251e6552de89aa71f2bb6cc3ab683c63dafc8662f5b8afa23aefac8a16040ff7e014",
    "a2feaf67374372b1cc98a3fcd777884172533f644e5126203c8d3fc9ad8989d546eda4f1",
    "57d6b91e96356ec92e579a5746a5521949af917f86ce74555ce8bec9c08153d78541751b",
    "b4817c2dcaa4622611d6a4e5bec5bec0da44234a41ab01679d31661e6b7ca31f5eaf4517",
    "45ee778eb55fe7bfa3b905afa4cb35edcf90ae2ca51ac21aab0163af6b3418781be28a96",
    "c7805e68b910c237aa85080d5ebbd8ae702d5706d9a8b6a412ab6ba6e7f1effda340243b",
    "f2d551b5754b9ea6b85b488c2f6e240124a33e0fc0fb1b02d77f121d04493bee7cbb2060",
    "ca10dbad0e6bcbfe046f836c68ae8557eedf5a7618ac6ac1c0eddec6000e7f462f94b97d",
    "3733aa312a7097823165fe978665bc3376053ac837afd6fc8b68f9c804ac066d13e89454",
    "3d53b6ff9348e3621fe5ae0dbf89e5d265f2fb1900acec9574bde08a8c51f8df69b876f0",
    "f71efaed50f848ce26cd3958f7a073b12a6d4c659dab739f5d85a1ee768d81a891953872",
    "5495bd396dbc5456fb72d482dc1454bee6d1e26c739341b19206ce70b949d5c08221536a",
    "52234c594b0bbe4a407112a60f10f0a22ef9828367e79f4b031a8b406fb94ce499c6dd6e",
    "92429d7eabdaa5ea11472ba65afcb58f28153b6550bc9456023136b3460847f63d267b2f",
    "856859ff5c05b68f7e41b68a0a99ad76b07a82ab4bd77adf28eb792a850149eb3c35383f",
    "f0998ecf85ab9b39589e69da8a2a051e4b145ea899a71e1ac7b37e48a3b812b98c8e2c87",
    "775a709b0943257ef5df22517cea252cc5589e71d5f68067d5ceebfccf3902bebb6f848d",
    "64a95211127ec547ed6ba5844edc8f59ec95f320109b91aa9a288db2ca6587f45cfa10bc",
    "335e5478cbe5ed464df6ab995546be862588033299910409633a8fa5d178e382b58785c8",
    "b049cdb931b092fc6ad9831a4019b69db91c1ec8b5433b5020f0a6b8b2a4c14c2aaf1355",
    "16fa99273302db0943c23f2519b2e9103a028b4bd48285aef4bf31a20de568bcbec50846",
    "7910f608cefd72a1d024ba88b99a6861bfc630baa25596093613a68a87b9e405267b8c3c",
    "f3e9d219ba9137c10b8de8433300a1496de147fb2e4972a05f597bd60049344b3affa812",
    "992c2b6e174cd68e7f72f04484d290b75676361baae94e7c3fe75676af0427ddab6d8ff6",
    "3a453d0e4f519f68e8579842ffcec2cc907edc493869167d4098a382a0b09d5d6265ceb1",
    "ca68a9655c6f3dfad0d2988f5a3cd0b7192f3a9ddae14311b5a310aa68000338129e63ee",
    "622ceeeb4b6d0fd4ccd2dbc4ed3260d95e29017b91e22131599cd18dba04548ab7b31f47",
    "fae4772b00da51cea3ca4785f3035a7c86ab421d706ac7b51bbe52773295e04cf9eac29d",
    "558b68430ae27c104dfff2ff5056a798cd96858f6016957cdea721d31ca65113ae7c9ae4",
    "b27563c8223fe6a2f9cb9b68684d3a952fe41c8fd7c43934896bdc43aca3395db6b59683",
    "5954611b272cf2b56fd8b969377b77a07594e22d101ef4ce86bf31415185870189fac3b5",
    "e4740f439cd91f718462fc079c6ea6ab6148f42ea6fdda8e2f1d5fc3b66a4dac3ce287e4",
    "55d68de20cd67a0623d6230ea26cc047929035ad58b9d961c3e7e60290cbcc391dbca622",
    "9aedebe9eb063956e4c00a0d52ed8bba1e6796f3977319ccdcbd70bd8afa3dd5a8ea15b1",
    "64603c34fdbc2074a5de0a16cea3def17473d5bff46f2263998c211c64e45563ecd1dd1c",
    "1ac7c8bdef686b0359863a354f799876a094576ee2dbba657abc6bdad88013a111cd0760",
    "83785d1aa205b76b0848d9303e2f7a2d91e4cc6aa5b962f2c3ed92d858d7a311e5c7519b",
    "f2d0ae81ade86151681d077cb9ca036ecd3b26091efb4e0769982532947c7572d13f54cf",
    "3e6dc0cccee4f53d5f48b1c117aa027d6cbc249c2f40daad2ff4435b8acd7747993b998d",
    "c8d9439071f0ed66c17a2b3f0e5f3d47673c19cc2e62b0bf271b0b81ad3d3c0b749334fb",
    "68077328206374fa4907f629e37d2ecf975c8f2b8d655d3534383fc5c407a70b6010c895",
    "ce4f15fa8247870f2582f71242363c50ff1ca9ebad78de8d9e116d9df5cc589fec869151",
    "e62340be96c312b8a6ac1de715ab02d0abc170c9148d1ab5bb369181c5657c30bbbc0246",
    "35b4dbc7f7f5933defcca255e6d3421981ef395544ca8fadc8e5f34b4f97f5e2adfb4ca0",
    "9edf2ebd2d5f9fb52e0eafd4b0cb5f5c92d4d339a01ecc23e99cdaa4da1f36a6b1f49d7d",
    "b9cd6de061c59419b05848a84455e6d2f5ce92d6a6d97cac5db0cd8b4054deb20f1d8539",
    "f08ba0cece0241aee427ad2a20d0f0186769a130c60344fafe621ca5c580073503d59cd5",
    "f1e903d40a94db9192f5b82923ae172a7aac99fb6e635b657a32c3daa649a0aa51491b80",
    "3812e69d37294772fec9d5e7981781babf5ec5a694e5686cf8edd56abfd3dcac15afc77e",
    "29ddf7e620365a3d33b866fc785783cada4c07ec321acd12b62af82a9d45d869547bae36",
    "85f79eb28ce11b6d5fdb99432b0978156aadce1f03d930525e3655f4ba9da51a94707fb3",
    "5def265f721a018fb8907c1c68272f327622fb34f258e0a5ad463c2c548ec96358e02625",
    "66c331376a76d26f4090b1c42fbb3f2a643ad01cbad597fe09930179fc7b047e16b2b32c",
    "b2edc3ba33956eb37aa968c170d5c37211d6e427235d6f4052c7632bee4efccfac01fe43",
    "17ab047a0e8dbf4e63d48f1667613a04acce1a92069b740958493b3b90a0a1de481f76bb",
    "66019f5374239578e9a660b17935a4e238430f38ec103d55484367ba9c5f7318a7d46375",
    "9e2f20cafb0cbbb9f4ead714438258e80a0d95c9e320903d07fd4d334a5daae9cd408363",
    "5fc9bcc3d01fd1b93434af3089bf5d9474ee743b55459a7d46b38980fdb08683dbde7a80",
    "bde782b418061798b3921937fc4bbc4af12a488888ba3ce09b232a037ca1fa05b0f18306",
    "d80900f05234df1200d7a102119e5cd480967ab23883aaf4b7588ef8b7afebb34a0d3645",
    "c4269be6de17215b193775bd2f8b7bb54fb53899c8e8f11e8c90b0ad633c1d6526190764",
    "cc95d13b1b4eb1cfccf0487dcfa06a0dbaf8843a1bc80d8dd49b3a3ebc54f4f0d21ae8af",
    "c9079393e7341ec43ee929cd8204c5021e63dbcc911676a10f60fa42e89e39a5bd95bf6a",
    "ce53df8d9f866a5e21f4a5d28a0fda8d1d654f274e6551086b00535b8e96cd6cfb5f9d63",
    "3d44660be4b8daeeceafeb31406a5bb2f60164c8525c13ef6c20aa59ee4b619cd79ff46b",
    "31ac07f77fc4fa2fd1198f7329694b611475a280e22d839cb478b5c8fb8d2fe994fe917f",
    "56e43e09680c3d6d7cad06a0bf96ea48729732cd81e709db022e912adbd0e0924b17b228",
    "6491a5859ff1b0243399cd89f5b688d4a8711fee4338a68ba9bc7948fd4fd7c597ba1647",
    "a66054c12b9145ecb84008ccbbc0577b60fc784d9fe9cedc64ac11a38f3212457085aef4",
    "112a80248d453a934e4d3a4b461a5651e70a95c8edec9976cd7aadbf73d279b557170641",
    "7edfea60ef645faf2fb0836b6e240652c9b946af449f150b43ceb74c0166a503b55891fb",
    "ca7276fca96178a7c12a108487cff04167d4a836e4ef022036892f19ade7b76f82b9dbdf",
    "731afec1c1eb8134c85212c689fd240ea2edc0f4b01c82f1e510dbd8f788912a24db559b",
    "04b9b878d0700cdd7f1d73fa9cf42c931706c9dc8a2ed627b76b3459ed201ff69764b02e",
    "cd7f0c948f2e42738d400569ce75da776b4d645aaecf3123d72527909c398367bbe5bbe3",
    "8e1b21fcad53efe9aa35a45fc47fd9eea568b4bf30a51987180874a37c913910a8957605",
    "6148f908bce1f15162b60e5fcca85826c7a4144c74e002203b414b7e68bbb60f2f11d420",
    "e3702e247da75cbe64bba45a9273eda7a91acf26006f52f5b2aaece00cd6b9c3ec49db81",
    "24aa66536883c5a3fbbd3f62e7dfb22a4302bdd602e046e68227ada72d0079f509601427",
    "7486cb4a9fad231835485d4d5be85b454761f838d4045acb7ef8338bf83b0ed425f8a482",
    "d09121a7874aca5b03ae2d146b1fb5fa0500150b1e9d3afa2532045ca7ac0d424e147b33",
    "e10474b2778ed27a9c154b7a22f966020c115440f2bbfd056bb9bbd6dc7eeab2f94140ba",
    "901d138a33d6c1b59c981f2fe7368fccd367c122894c6c81a843a48dcb0b7ff40460dae1",
    "5a08392755312c1aa927f3330000",
);

#[test]
fn borrowed_signer_finalizes_one_key_fixture_to_exact_expected_values() {
    let (catalog, fixture, spend_key) = one_key_signable_fixture();
    let expected_public_key = BitcoinPublicKey::from(PublicKey::from_secret_key(
        &Secp256k1::<All>::new(),
        &spend_key,
    ));
    let mut provider = common::FixtureOpeningProvider::new(&fixture);
    let mut rng = StdRng::from_seed(synthetic_material(
        b"ordinary wallet borrowed signer one-key exact evidence",
    ));
    let mut signer = BorrowedOrdinaryP2wpkhSigner::new(BorrowedOrdinarySpendKey::new(&spend_key));

    let finalized = expect_finalized(build_sign_and_finalize_ordinary_wallet_transaction(
        &catalog,
        &mut provider,
        selected_batch(&fixture, &[1, 0]),
        planned_outputs(&fixture),
        ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
        &mut rng,
        &mut signer,
    ));

    let transaction = finalized.transaction();
    let expected_outpoints = [1, 0].map(|vout| OutPoint::new(fixture.transaction.txid(), vout));
    assert_eq!(
        transaction
            .input
            .iter()
            .map(|input| input.previous_output)
            .collect::<Vec<_>>(),
        expected_outpoints
    );
    assert_eq!(provider.calls(), 2);
    for input in &transaction.input {
        assert!(input.script_sig.is_empty());
        let witness = input.witness.script_witness.to_vec();
        assert_eq!(witness.len(), 2);
        assert!(
            witness[0].len() >= 2 && witness[0].len() <= 73,
            "native P2WPKH signature witness shape"
        );
        assert_eq!(witness[1], expected_public_key.to_bytes());
    }
    assert_one_key_finalized_valid(&finalized, &fixture.transaction);

    assert_eq!(finalized.txid().to_string(), EXPECTED_ONE_KEY_TXID);
    assert_eq!(finalized.wtxid().to_string(), EXPECTED_ONE_KEY_WTXID);
    assert_eq!(
        hex_encode(&finalized.serialize_for_broadcast()),
        EXPECTED_ONE_KEY_BROADCAST_HEX
    );
}

#[test]
fn borrowed_signer_public_key_matches_and_owns_the_fixture_script() {
    let (_, fixture, spend_key) = one_key_signable_fixture();
    let secp = Secp256k1::<All>::new();
    let expected_public_key = BitcoinPublicKey::from(PublicKey::from_secret_key(&secp, &spend_key));
    let owned_script = Script::new_v0_wpkh(&expected_public_key.wpubkey_hash().unwrap());
    let mut signer = BorrowedOrdinaryP2wpkhSigner::new(BorrowedOrdinarySpendKey::new(&spend_key));

    for (input_index, vout) in [(0_usize, 1_u32), (1, 0)] {
        let outpoint = OutPoint::new(fixture.transaction.txid(), vout);
        let returned = signer
            .public_key(input_index, &outpoint)
            .unwrap_or_else(|| panic!("input {input_index} public key request refused"));
        assert_eq!(returned, expected_public_key);
        assert!(returned.compressed);
        let witness_hash = returned
            .wpubkey_hash()
            .unwrap_or_else(|_| panic!("input {input_index} returned an uncompressed key"));
        assert_eq!(Script::new_v0_wpkh(&witness_hash), owned_script);
        assert_eq!(
            fixture.transaction.output[vout as usize].script_pubkey, owned_script,
            "the returned key passes the product ownership check against the previous output"
        );
    }
}

#[test]
fn borrowed_signer_wrong_key_reaches_public_key_does_not_own_input_with_retryable_pset() {
    let (catalog, fixture, spend_key) = one_key_signable_fixture();
    let seed = synthetic_material(b"ordinary wallet borrowed signer wrong-key layout");
    let mut baseline_provider = common::FixtureOpeningProvider::new(&fixture);
    let mut baseline_rng = StdRng::from_seed(seed);
    let baseline = build_blinded_ordinary_wallet_pset(
        &catalog,
        &mut baseline_provider,
        selected_batch(&fixture, &[1, 0]),
        planned_outputs(&fixture),
        ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
        &mut baseline_rng,
    )
    .unwrap();
    let baseline_bytes = baseline.serialize_sensitive();
    drop(baseline);

    let wrong_key_bytes = synthetic_material(b"ordinary wallet borrowed signer wrong spend key");
    let wrong_key = SecretKey::from_slice(&wrong_key_bytes).unwrap();
    let mut wrong_key_signer =
        BorrowedOrdinaryP2wpkhSigner::new(BorrowedOrdinarySpendKey::new(&wrong_key));
    let mut wrong_key_provider = common::FixtureOpeningProvider::new(&fixture);
    let mut wrong_key_rng = StdRng::from_seed(seed);
    let failure = expect_transaction_failure(build_sign_and_finalize_ordinary_wallet_transaction(
        &catalog,
        &mut wrong_key_provider,
        selected_batch(&fixture, &[1, 0]),
        planned_outputs(&fixture),
        ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
        &mut wrong_key_rng,
        &mut wrong_key_signer,
    ));

    assert_eq!(
        failure.reason(),
        &OrdinaryWalletTransactionReason::Signing(OrdinarySigningError::PublicKeyDoesNotOwnInput)
    );
    let retryable = failure.into_retryable_blinded().unwrap();
    assert_eq!(
        retryable.serialize_sensitive(),
        baseline_bytes,
        "the retryable blinded PSET is recovered byte-identical and unmodified"
    );

    let mut retry_signer =
        BorrowedOrdinaryP2wpkhSigner::new(BorrowedOrdinarySpendKey::new(&spend_key));
    let secp = Secp256k1::new();
    let signed = match retryable.sign_and_finalize(&secp, &mut retry_signer) {
        Ok(signed) => signed,
        Err(_) => panic!("the recovered blinded PSET must retry into finalization"),
    };
    assert_one_key_finalized_valid(&signed.into_finalized_transaction(), &fixture.transaction);
}

#[test]
fn borrowed_signer_refuses_foreign_sighash_types_with_indistinguishable_none() {
    let (_, _, spend_key) = one_key_signable_fixture();
    let secp = Secp256k1::<All>::new();
    let outpoint = OutPoint::new(
        Txid::from_byte_array(synthetic_material(
            b"ordinary wallet borrowed signer refusal outpoint",
        )),
        0,
    );
    let digest = synthetic_material(b"ordinary wallet borrowed signer refusal digest");
    let mut signer = BorrowedOrdinaryP2wpkhSigner::new(BorrowedOrdinarySpendKey::new(&spend_key));

    let baseline = signer
        .sign_digest(0, &outpoint, digest, ORDINARY_SIGHASH_TYPE)
        .unwrap_or_else(|| panic!("the pinned sighash type must sign"));
    assert_eq!(
        baseline,
        secp.sign_ecdsa(&Message::from_digest(digest), &spend_key),
        "deterministic RFC 6979 signing retains no per-call state"
    );
    for foreign_sighash_type in [
        EcdsaSighashType::All,
        EcdsaSighashType::None,
        EcdsaSighashType::Single,
        EcdsaSighashType::AllPlusAnyoneCanPay,
    ] {
        assert!(
            signer
                .sign_digest(0, &outpoint, digest, foreign_sighash_type)
                .is_none(),
            "every foreign sighash type refuses with the same redacted none"
        );
    }
    assert_eq!(
        signer.sign_digest(0, &outpoint, digest, ORDINARY_SIGHASH_TYPE),
        Some(baseline),
        "a refusal leaves no distinguishing state behind"
    );
}

#[test]
fn borrowed_signer_drives_consecutive_inputs_and_operations_without_retained_state() {
    let (catalog, fixture, spend_key) = one_key_signable_fixture();
    let mut signer = BorrowedOrdinaryP2wpkhSigner::new(BorrowedOrdinarySpendKey::new(&spend_key));
    let seed = synthetic_material(b"ordinary wallet borrowed signer consecutive operations");

    let mut finalized = Vec::with_capacity(2);
    for operation in 0..2 {
        let mut provider = common::FixtureOpeningProvider::new(&fixture);
        let mut rng = StdRng::from_seed(seed);
        let signed = expect_finalized(build_sign_and_finalize_ordinary_wallet_transaction(
            &catalog,
            &mut provider,
            selected_batch(&fixture, &[1, 0]),
            planned_outputs(&fixture),
            ExplicitFee::new(fixture.fee_asset, 100).unwrap(),
            &mut rng,
            &mut signer,
        ));
        assert_eq!(
            provider.calls(),
            2,
            "operation {operation} opens both inputs"
        );
        finalized.push(signed);
    }

    assert_eq!(finalized[0].txid(), finalized[1].txid());
    assert_eq!(finalized[0].wtxid(), finalized[1].wtxid());
    assert_eq!(
        finalized[0].serialize_for_broadcast(),
        finalized[1].serialize_for_broadcast(),
        "two consecutive complete operations through one stateless signer agree byte for byte"
    );

    let transaction = finalized[0].transaction();
    assert_eq!(
        transaction.input.len(),
        2,
        "two consecutive inputs sign in one operation"
    );
    let secp = Secp256k1::<All>::new();
    let expected_public_key = BitcoinPublicKey::from(PublicKey::from_secret_key(&secp, &spend_key));
    let mut sighash_cache = SighashCache::new(transaction);
    for input_index in 0..transaction.input.len() {
        let witness = transaction.input[input_index]
            .witness
            .script_witness
            .to_vec();
        assert_eq!(witness.len(), 2);
        let (signature, sighash_byte) = witness[0].split_at(witness[0].len() - 1);
        assert_eq!(sighash_byte, [ORDINARY_SIGHASH_TYPE.as_u32() as u8]);
        let signature = ecdsa::Signature::from_der(signature)
            .unwrap_or_else(|_| panic!("input {input_index} carries strict DER"));
        assert_eq!(witness[1], expected_public_key.to_bytes());
        let previous_output = &fixture.transaction.output
            [transaction.input[input_index].previous_output.vout as usize];
        let script_code = Script::new_p2pkh(&expected_public_key.pubkey_hash());
        let digest = sighash_cache
            .segwitv0_sighash_with_rangeproof_mode(
                input_index,
                &script_code,
                previous_output.value,
                ORDINARY_SIGHASH_TYPE,
                SighashRangeproofMode::Enabled,
            )
            .to_byte_array();
        secp.verify_ecdsa(
            &Message::from_digest(digest),
            &signature,
            &expected_public_key.inner,
        )
        .unwrap_or_else(|_| panic!("input {input_index} signature verifies"));
    }
    assert_one_key_finalized_valid(&finalized[0], &fixture.transaction);
}

fn one_key_signable_fixture() -> (DescriptorCatalog, common::FundingFixture, SecretKey) {
    let mut seed = synthetic_material(b"ordinary wallet borrowed signer one-key descriptor seed");
    let mut root = Xpriv::new_master(NetworkKind::Test, &seed).unwrap();
    seed.fill(0);
    let secp = miniscript::bitcoin::secp256k1::Secp256k1::new();
    let public = Xpub::from_priv(&secp, &root);
    let descriptor = format!("elwpkh({public}/<0;1>/*)");
    let catalog = DescriptorCatalog::derive(&descriptor, DescriptorNetwork::Test, 1).unwrap();
    let mut child = root
        .derive_priv(
            &secp,
            &DerivationPath::from(vec![
                ChildNumber::Normal { index: 0 },
                ChildNumber::Normal { index: 0 },
            ]),
        )
        .unwrap();
    let spend_key = SecretKey::from_slice(&child.private_key.secret_bytes()).unwrap();
    child.private_key.non_secure_erase();
    root.private_key.non_secure_erase();
    let signing_secp = Secp256k1::new();
    let public_key = BitcoinPublicKey::new(spend_key.public_key(&signing_secp));
    let script = Script::new_v0_wpkh(&public_key.wpubkey_hash().unwrap());
    let fixture = one_key_funding_fixture([script.clone(), script]);
    (catalog, fixture, spend_key)
}

fn one_key_funding_fixture(scripts: [Script; 2]) -> common::FundingFixture {
    let slip77 = synthetic_material(b"ordinary wallet PSET SLIP77 material");
    let fee_asset = AssetId::LIQUIDTESTNET_BTC;
    let second_asset = AssetId::from_byte_array([0x82; 32]);
    let previous = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![
            explicit_output(fee_asset, 1_000, Script::from(vec![0x51])),
            explicit_output(second_asset, 2_000, Script::from(vec![0x51])),
        ],
    };
    let spent_secrets = [
        TxOutSecrets::new(
            fee_asset,
            AssetBlindingFactor::zero(),
            1_000,
            ValueBlindingFactor::zero(),
        ),
        TxOutSecrets::new(
            second_asset,
            AssetBlindingFactor::zero(),
            2_000,
            ValueBlindingFactor::zero(),
        ),
    ];
    let secp = Secp256k1::new();
    let external_key = fixture_blinding_key(&slip77, scripts[0].as_bytes());
    let internal_key = fixture_blinding_key(&slip77, scripts[1].as_bytes());
    let external_address = Address::from_script(
        &scripts[0],
        Some(external_key.public_key(&secp)),
        &AddressParams::ELEMENTS,
    )
    .unwrap();
    let mut rng = StdRng::from_seed(synthetic_material(
        b"ordinary wallet PSET funding fixture randomness",
    ));
    let (first_output, first_abf, first_vbf, _) = TxOut::new_not_last_confidential(
        &mut rng,
        &secp,
        900,
        &external_address,
        fee_asset,
        &spent_secrets,
    )
    .unwrap();
    let first_output_secrets = TxOutSecrets::new(fee_asset, first_abf, 900, first_vbf);
    let fee_secrets = TxOutSecrets::new(
        fee_asset,
        AssetBlindingFactor::zero(),
        100,
        ValueBlindingFactor::zero(),
    );
    let (second_output, _, _, _) = TxOut::new_last_confidential(
        &mut rng,
        &secp,
        2_000,
        second_asset,
        scripts[1].clone(),
        internal_key.public_key(&secp),
        &spent_secrets,
        &[&first_output_secrets, &fee_secrets],
    )
    .unwrap();
    let transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![
            common_input(OutPoint::new(previous.txid(), 0)),
            common_input(OutPoint::new(previous.txid(), 1)),
        ],
        output: vec![first_output, second_output, TxOut::new_fee(100, fee_asset)],
    };

    common::FundingFixture {
        transaction_bytes: serialize(&transaction),
        previous_transaction_bytes: serialize(&previous),
        transaction,
        fee_asset,
        second_asset,
        slip77,
    }
}

fn fixture_blinding_key(master_key: &[u8; 32], script: &[u8]) -> SecretKey {
    let mut inner_pad = [0x36; 64];
    let mut outer_pad = [0x5c; 64];
    for (index, key_byte) in master_key.iter().enumerate() {
        inner_pad[index] ^= key_byte;
        outer_pad[index] ^= key_byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(script);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    SecretKey::from_slice(&outer.finalize()).unwrap()
}

fn explicit_output(asset: AssetId, value: u64, script_pubkey: Script) -> elements::TxOut {
    elements::TxOut {
        asset: Asset::Explicit(asset),
        value: Value::Explicit(value),
        nonce: Nonce::Null,
        script_pubkey,
        witness: elements::TxOutWitness::default(),
    }
}

fn common_input(previous_output: OutPoint) -> elements::TxIn {
    elements::TxIn {
        previous_output,
        is_pegin: false,
        script_sig: Script::new(),
        sequence: elements::Sequence::MAX,
        asset_issuance: Default::default(),
        witness: Default::default(),
    }
}

fn assert_one_key_finalized_valid(
    finalized: &FinalizedOrdinaryTransaction,
    funding_transaction: &Transaction,
) {
    let secp = Secp256k1::new();
    let transaction = finalized.transaction();
    for input in &transaction.input {
        assert!(input.script_sig.is_empty());
        assert_eq!(input.witness.script_witness.to_vec().len(), 2);
    }
    for output in &transaction.output[..transaction.output.len() - 1] {
        assert!(output.asset.is_confidential());
        assert!(output.value.is_confidential());
        assert!(output.nonce.is_confidential());
        assert!(!output.witness.rangeproof.is_empty());
        assert!(!output.witness.surjection_proof.is_empty());
    }
    let fee = transaction.output.last().unwrap();
    assert!(fee.script_pubkey.is_empty());
    assert!(fee.asset.is_explicit());
    assert!(fee.value.is_explicit());
    let previous_outputs = transaction
        .input
        .iter()
        .map(|input| {
            assert_eq!(input.previous_output.txid, funding_transaction.txid());
            funding_transaction.output[input.previous_output.vout as usize].clone()
        })
        .collect::<Vec<_>>();
    transaction
        .verify_tx_amt_proofs(&secp, &previous_outputs)
        .unwrap();

    let broadcast = finalized.serialize_for_broadcast();
    let decoded: Transaction = deserialize(&broadcast).unwrap();
    assert_eq!(decoded, *transaction);
    assert!(deserialize::<elements::pset::PartiallySignedTransaction>(&broadcast).is_err());
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn expect_finalized(
    result: Result<FinalizedOrdinaryTransaction, OrdinaryWalletTransactionFailure>,
) -> FinalizedOrdinaryTransaction {
    match result {
        Ok(finalized) => finalized,
        Err(_) => panic!("ordinary wallet transaction unexpectedly failed"),
    }
}

fn expect_transaction_failure(
    result: Result<FinalizedOrdinaryTransaction, OrdinaryWalletTransactionFailure>,
) -> OrdinaryWalletTransactionFailure {
    match result {
        Ok(_) => panic!("ordinary wallet transaction unexpectedly succeeded"),
        Err(failure) => failure,
    }
}
