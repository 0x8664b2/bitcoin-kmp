package fr.acinq.bitcoin

import fr.acinq.bitcoin.Bitcoin.addressToPublicKeyScript
import fr.acinq.bitcoin.Transaction.Companion.hashForSigningSchnorr
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TaprootTestsCommon {
    @Test
    fun `check taproot signatures`() {
        // derive BIP86 wallet key
        val (_, master) = DeterministicWallet.ExtendedPrivateKey.decode("tprv8ZgxMBicQKsPeQQADibg4WF7mEasy3piWZUHyThAzJCPNgMHDVYhTCVfev3jFbDhcYm4GimeFMbbi9z1d9rfY1aL5wfJ9mNebQ4thJ62EJb")
        val key = DeterministicWallet.derivePrivateKey(master, "86'/1'/0'/0/1")
        val internalKey = XonlyPublicKey(key.publicKey)
        val outputKey = internalKey.outputKey(null)
        assertEquals("tb1phlhs7afhqzkgv0n537xs939s687826vn8l24ldkrckvwsnlj3d7qj6u57c", Bech32.encodeWitnessAddress("tb", 1, outputKey.value.toByteArray()))

        // tx sends to tb1phlhs7afhqzkgv0n537xs939s687826vn8l24ldkrckvwsnlj3d7qj6u57c
        val tx =
            Transaction.read("02000000000101590c995983abb86d8196f57357f2aac0e6cc6144d8239fd8a171810b476269d50000000000feffffff02a086010000000000225120bfef0f753700ac863e748f8d02c4b0d1fc7569933fd55fb6c3c598e84ff28b7c13d3abe65a060000160014353b5487959c58f5feafe63800057899f9ece4280247304402200b20c43175358c970850a583fd60d36c06588f1103b82b0968dc21e20e7d7958022027c64923623205c4985541d4a9fc6b5df4111d918fe63803337538b029c17ea20121022f685476d299e7b49d3a6b380e10aec1f93d96819fd7697669fabb533cc052624ff50000")
        assertEquals(Script.pay2tr(outputKey), Script.parse(tx.txOut[0].publicKeyScript))

        // tx1 spends tx using key path spending i.e its witness just includes a single signature that is valid for outputKey
        val tx1 =
            Transaction.read("020000000001018cd229daf76b9733dad3f4d183809f6594abb788a1bf07f04d6e889d2040dbc00000000000fdffffff011086010000000000225120bfef0f753700ac863e748f8d02c4b0d1fc7569933fd55fb6c3c598e84ff28b7c01407f330922263a3f281e111bf8583964644ef7f694494d028de546b162cbd68591ab38f9626a8922dc20a84776dc9bd8a21dc5c64ffc5fa6f28f0d42ed2e5ffb7dcef50000")
        val sig = tx1.txIn[0].witness.stack.first()
        val sighashType: Int = when {
            sig.size() == 65 -> sig[64].toInt()
            else -> 0
        }

        // check that tx1's signature is valid
        val hash = hashForSigningSchnorr(tx1, 0, listOf(tx.txOut.first()), sighashType, SigVersion.SIGVERSION_TAPROOT, null)
        assertTrue(Secp256k1.verifySchnorr(sig.toByteArray(), hash.toByteArray(), outputKey.value.toByteArray()))

        // re-create signature
        val priv = key.privateKey.tweak(internalKey.tweak(null))
        // here auxiliary random data is set to null, which does not the same result as using all-zero random data
        // this is being changed in bitcoin core, so that null == all zeros
        val ourSig = Secp256k1.signSchnorr(hash.toByteArray(), priv.value.toByteArray(), null)
        assertTrue(Secp256k1.verifySchnorr(ourSig, hash.toByteArray(), outputKey.value.toByteArray()))

        // generate another sig with all zero random data, and check that it is valid too
        val ourSig1 = Secp256k1.signSchnorr(hash.toByteArray(), priv.value.toByteArray(), Hex.decode("0000000000000000000000000000000000000000000000000000000000000000"))
        assertTrue(Secp256k1.verifySchnorr(ourSig1, hash.toByteArray(), outputKey.value.toByteArray()))
    }

    @Test
    fun `send to and spend from taproot addresses`() {
        val privateKey = PrivateKey(ByteVector32("0101010101010101010101010101010101010101010101010101010101010101"))
        val internalKey = XonlyPublicKey(privateKey.publicKey())
        val outputKey = internalKey.outputKey(null)
        val address = Bech32.encodeWitnessAddress("tb", 1, outputKey.value.toByteArray())
        assertEquals("tb1p33wm0auhr9kkahzd6l0kqj85af4cswn276hsxg6zpz85xe2r0y8snwrkwy", address)

        // this tx sends to tb1p33wm0auhr9kkahzd6l0kqj85af4cswn276hsxg6zpz85xe2r0y8snwrkwy
        val tx =
            Transaction.read("02000000000101bf77ef36f2c0f32e0822cef0514948254997495a34bfba7dd4a73aabfcbb87900000000000fdffffff02c2c2000000000000160014b5c3dbfeb8e7d0c809c3ba3f815fd430777ef4be50c30000000000002251208c5db7f797196d6edc4dd7df6048f4ea6b883a6af6af032342088f436543790f0140583f758bea307216e03c1f54c3c6088e8923c8e1c89d96679fb00de9e808a79d0fba1cc3f9521cb686e8f43fb37cc6429f2e1480c70cc25ecb4ac0dde8921a01f1f70000")
        assertEquals(Script.pay2tr(outputKey), Script.parse(tx.txOut[1].publicKeyScript))

        // we want to spend
        val outputScript = addressToPublicKeyScript(Block.TestnetGenesisBlock.hash, "tb1pn3g330w4n5eut7d4vxq0pp303267qc6vg8d2e0ctjuqre06gs3yqnc5yx0")
        val tx1 = Transaction(
            2,
            listOf(TxIn(OutPoint(tx, 1), TxIn.SEQUENCE_FINAL)),
            listOf(TxOut(49258.sat(), outputScript)),
            0
        )
        val sigHashType = 0
        val hash = hashForSigningSchnorr(tx1, 0, listOf(tx.txOut[1]), sigHashType, 0, null)
        val priv = privateKey.tweak(internalKey.tweak(null))
        val sig = Secp256k1.signSchnorr(hash.toByteArray(), priv.value.toByteArray(), Hex.decode("0000000000000000000000000000000000000000000000000000000000000000"))
        val tx2 = tx1.updateWitness(0, ScriptWitness(listOf(sig.byteVector())))
        assertEquals(ByteVector32("4b88aacc747b4cc90bbc6db6e14f8efd0bdc9842deac6df34b7bbea912130806"), tx2.txid)
        Transaction.correctlySpends(tx2, tx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    @Test
    fun `spend pay-to-taproot transactions - 1`() {
        val tx1 = Transaction.read("01000000000101b9cb0da76784960e000d63f0453221aeeb6df97f2119d35c3051065bc9881eab0000000000fdffffff020000000000000000186a16546170726f6f74204654572120406269746275673432a059010000000000225120339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc00247304402204bf50f2fea3a2fbf4db8f0de602d9f41665fe153840c1b6f17c0c0abefa42f0b0220631fe0968b166b00cb3027c8817f50ce8353e9d5de43c29348b75b6600f231fc012102b14f0e661960252f8f37486e7fe27431c9f94627a617da66ca9678e6a2218ce1ffd30a00")
        val tx2 = Transaction.read("01000000000101d1f1c1f8cdf6759167b90f52c9ad358a369f95284e841d7a2536cef31c0549580100000000fdffffff020000000000000000316a2f49206c696b65205363686e6f7272207369677320616e6420492063616e6e6f74206c69652e204062697462756734329e06010000000000225120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f90140a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758773a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174affd30a00")
        Transaction.correctlySpends(tx2, tx1, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

   @Test
    fun `spend pay-to-taproot transactions - 2`() {
        val tx = Transaction.read("020000000001041ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890000000000ffffffff1ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890100000000ffffffff1ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890200000000ffffffff1ee2529c53a3c05c1e35fa853b9209cbc1a17be31aae9f4e7ea42d13f24c65890300000000ffffffff01007ea60000000000225120a457d0c0399b499ed2df571d612ba549ae7f199387edceac175999210f6aa39d0141b23008b3e044d16078fc93ae4f342b6e5ba44241c598503f80269fd66e7ce484e926b2ff58ac5633be79857951b3dc778082fd38a9e06a1139e6eea41a8680c7010141be98ba2a47fce6fbe4f7456e5fe0c2381f38ed3ae3b89d0748fdbfc6936b68019e01ff60343abbea025138e58aed2544dc8d3c0b2ccb35e2073fa2f9feeff5ed010141466d525b97733d4733220694bf747fd6e9d4b0b96ea3b2fb06b7486b4b8e864df0057481a01cf10f7ea06849fb4717d62b902fe5807a1cba03a46bf3a7087e940101418dbfbdd2c164005eceb0de04c317b9cae62b0c97ed33da9dcec6301fa0517939b9024eba99e22098a5b0d86eb7218957883ea9fc13b737e1146ae2b95185fcf90100000000")
        val parent = Transaction.read("020000000001013dc77d529549228b6544c09349c13eb64efa8c99e339bb3f2aa280c1e412e7b00000000000feffffff0540e13300000000002251205f4237bd79e8fe440d102a5e0c20a75160e96d42a8b19825ac90f73f1f6677685008340000000000225120e914be846f7afb29f5c3b24e5f630886ed5cbcc79a28888d91009be90924508d602f340000000000225120d9390cafa11bdeb19de21e0a2bbd541f4d0979473999503408d40814399b7f9100d40a0000000000225120e8d645f42be8700595c7cbb278602fb51471d5bb24ccd27668321b7affd167bfc8a22400000000002251201a8e36e17d0afa16139b900dc85f775d3c0c624a2786fbc05ba7db87f3a55fcd0247304402207d1c9b565cebdbbdcd5973f6f4281eb6d1fceb41f53af3c597d1deacb2086d0202204672e1a9d917456e4b8346910a031898b27f3f08221cd355cfd5ee3367c5086401210291b8fe7a5ffc27834002ccac2f62aeddff9bedb436756c2e511c5c573bb9ba4dffd30a00")
        Transaction.correctlySpends(tx, parent, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    @Test
    fun `spend pay-to-tapscript transactions - 1`() {
        val tx1 = Transaction.read("02000000000101cabda47f832e48eb5bce9ee03548f46cddb167f1d495310ffa8aac38940cfab90000000000fdffffff02e6800700000000002251205f4237bd7dae576b34abc8a9c6fa4f0e4787c04234ca963e9e96c8f9b67b56d1e6800700000000002251205f4237bd7f93c69403a30c6b641f27ccf5201090152fcf1596474221307831c30247304402206441af273f66f66cfbde93c150c8e163d20358559fd3ec6c201467d4c29d0bbd022008d923c3a70a93808695457e547f69bb3a0e6bcaeb53547d506825cc7cafd0f30121039ddfe17e14a1ae9a417d1cc7614449b3387d8d69ef3e12ce3f1dffce279d4884ffd30a00")
        val tx2 = Transaction.read("020000000001027bc0bba407bc67178f100e352bf6e047fae4cbf960d783586cb5e430b3b700e70000000000feffffff7bc0bba407bc67178f100e352bf6e047fae4cbf960d783586cb5e430b3b700e70100000000feffffff01b4ba0e0000000000160014173fd310e9db2c7e9550ce0f03f1e6c01d833aa90140134896c42cd95680b048845847c8054756861ffab7d4abab72f6508d67d1ec0c590287ec2161dd7884983286e1cd56ce65c08a24ee0476ede92678a93b1b180c03407b5d614a4610bf9196775791fcc589597ca066dcd10048e004cd4c7341bb4bb90cee4705192f3f7db524e8067a5222c7f09baf29ef6b805b8327ecd1e5ab83ca2220f5b059b9a72298ccbefff59d9b943f7e0fc91d8a3b944a95e7b6390cc99eb5f4ac41c0d9dfdf0fe3c83e9870095d67fff59a8056dad28c6dfb944bb71cf64b90ace9a7776b22a1185fb2dc9524f6b178e2693189bf01655d7f38f043923668dc5af45bffd30a00")
        Transaction.correctlySpends(tx2, tx1, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }

    @Test
    fun `spend pay-to-tapscript transactions - 2`() {
        val tx1 = Transaction.read("0200000000010140b84131c5c582290126bbd8b8e2e5bbd7c2681a4b01314f1b874ea1b5fdf81c0000000000ffffffff014c1d0000000000002251202fcad7470279652cc5f88b8908678d6f4d57af5627183b03fc8404cb4e16d88902473044022066d6939ea701db5d306fb948aea64af196ae52fc34d62c2e7992f62cdabc791402200abdac6766105457ceabcbe55a2d33f064d515210085f7af1248d273442e2b2a012103476f0d6a85ced4a85b08cbabbff28564a1ba31091b38f10b167f4fe1e1c9c4f900d40a00")
        val tx2 = Transaction.read("02000000000101b41b20295ac85fd2ae3e3d02900f1a1e7ddd6139b12e341386189c03d6f5795b0000000000fdffffff0100000000000000003c6a3a546878205361746f7368692120e2889e2f32316d696c20466972737420546170726f6f74206d756c7469736967207370656e64202d426974476f044123b1d4ff27b16af4b0fcb9672df671701a1a7f5a6bb7352b051f461edbc614aa6068b3e5313a174f90f3d95dc4e06f69bebd9cf5a3098fde034b01e69e8e788901400fd4a0d3f36a1f1074cb15838a48f572dc18d412d0f0f0fc1eeda9fa4820c942abb77e4d1a3c2b99ccf4ad29d9189e6e04a017fe611748464449f681bc38cf394420febe583fa77e49089f89b78fa8c116710715d6e40cc5f5a075ef1681550dd3c4ad20d0fa46cb883e940ac3dc5421f05b03859972639f51ed2eccbf3dc5a62e2e1b15ac41c02e44c9e47eaeb4bb313adecd11012dfad435cd72ce71f525329f24d75c5b9432774e148e9209baf3f1656a46986d5f38ddf4e20912c6ac28f48d6bf747469fb100000000")
        Transaction.correctlySpends(tx2, tx1, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }
}