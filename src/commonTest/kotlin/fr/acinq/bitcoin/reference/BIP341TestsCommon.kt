package fr.acinq.bitcoin.reference

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.io.ByteArrayOutput
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlinx.serialization.json.*
import kotlin.test.Test
import kotlin.test.assertEquals

class BIP341TestsCommon {
    @Test
    fun `BIP341 reference tests (key path spending)`() {
        val tests = TransactionTestsCommon.readData("data/bip341_wallet_vectors.json").jsonObject["keyPathSpending"]!!
        tests.jsonArray.forEach { it ->
            //val fulledSignedTx = Transaction.read(it.jsonObject["auxiliary"]!!.jsonObject["fulledSignedTx"]!!.jsonPrimitive.content)
            val rawUnsignedTx = Transaction.read(it.jsonObject["given"]!!.jsonObject["rawUnsignedTx"]!!.jsonPrimitive.content)
            val utxosSpent = it.jsonObject["given"]!!.jsonObject["utxosSpent"]!!.jsonArray.map {
                TxOut(it.jsonObject["amountSats"]!!.jsonPrimitive.long.sat(), Hex.decode(it.jsonObject["scriptPubKey"]!!.jsonPrimitive.content))
            }
            val hashAmounts = it.jsonObject["intermediary"]!!.jsonObject["hashAmounts"]!!.jsonPrimitive.content
            val hashOutputs = it.jsonObject["intermediary"]!!.jsonObject["hashOutputs"]!!.jsonPrimitive.content
            val hashPrevouts = it.jsonObject["intermediary"]!!.jsonObject["hashPrevouts"]!!.jsonPrimitive.content
            val hashScriptPubkeys = it.jsonObject["intermediary"]!!.jsonObject["hashScriptPubkeys"]!!.jsonPrimitive.content
            val hashSequences = it.jsonObject["intermediary"]!!.jsonObject["hashSequences"]!!.jsonPrimitive.content

            assertEquals(hashAmounts, Hex.encode(Transaction.amountsSha256(utxosSpent)))
            assertEquals(hashOutputs, Hex.encode(Transaction.outputsSha256(rawUnsignedTx)))
            assertEquals(hashPrevouts, Hex.encode(Transaction.prevoutsSha256(rawUnsignedTx)))
            assertEquals(hashScriptPubkeys, Hex.encode(Transaction.scriptPubkeysSha256(utxosSpent)))
            assertEquals(hashSequences, Hex.encode(Transaction.sequencesSha256(rawUnsignedTx)))

            it.jsonObject["inputSpending"]!!.jsonArray.forEach {
                val given = it.jsonObject["given"]!!.jsonObject
                val hashType = given["hashType"]!!.jsonPrimitive.int
                val txinIndex = given["txinIndex"]!!.jsonPrimitive.int
                val internalPrivkey = PrivateKey.fromHex(given["internalPrivkey"]!!.jsonPrimitive.content)
                val merkleRoot = nullOrBytes(given["merkleRoot"]?.jsonPrimitive?.content)

                val internalPubkey = XonlyPublicKey(internalPrivkey.publicKey())
                val intermediary = it.jsonObject["intermediary"]!!.jsonObject
                assertEquals(ByteVector32(intermediary["internalPubkey"]!!.jsonPrimitive.content), internalPubkey.value)
                assertEquals(ByteVector32(intermediary["tweak"]!!.jsonPrimitive.content), internalPubkey.tweak(merkleRoot))

                val tweakedPrivateKey = internalPrivkey.tweak(internalPubkey.tweak(merkleRoot))
                assertEquals(ByteVector32(intermediary["tweakedPrivkey"]!!.jsonPrimitive.content), tweakedPrivateKey.value)

                val hash = Transaction.hashForSigningSchnorr(rawUnsignedTx, txinIndex, utxosSpent, hashType, 0, null)
                assertEquals(ByteVector32(intermediary["sigHash"]!!.jsonPrimitive.content), hash)

                val sig = Secp256k1.signSchnorr(hash.toByteArray(), tweakedPrivateKey.value.toByteArray(), Hex.decode("0000000000000000000000000000000000000000000000000000000000000000"))
                val witness = when (hashType) {
                    SigHash.SIGHASH_DEFAULT -> sig.byteVector()
                    else -> (sig + byteArrayOf(hashType.toByte())).byteVector()
                }
                val expected = it.jsonObject["expected"]!!.jsonObject
                val witnessStack = expected["witness"]!!.jsonArray.map { ByteVector(it.jsonPrimitive.content) }
                assertEquals(1, witnessStack.size)
                assertEquals(witnessStack.first(), witness)
            }
        }
    }

    @Test
    fun `BIP341 reference tests (script path spending)`() {
        val tests = TransactionTestsCommon.readData("data/bip341_wallet_vectors.json").jsonObject["scriptPubKey"]!!
        tests.jsonArray.forEach { it ->
            val given = it.jsonObject["given"]!!.jsonObject
            val internalPubkey = XonlyPublicKey(ByteVector32.fromValidHex(given["internalPubkey"]!!.jsonPrimitive.content))
            val json = it.jsonObject["given"]!!.jsonObject["scriptTree"]
            val scriptTree = when(json) {
                null, JsonNull-> null
                else -> TreeNode.read(json) { ScriptElement.fromJson(it) }
            }

            val intermediary = it.jsonObject["intermediary"]!!.jsonObject
            val merkleRoot = scriptTree?.let { TreeNode.hash(it) }
            val tweakedKey = internalPubkey.outputKey(merkleRoot)
            merkleRoot?.let { assertEquals(ByteVector32(intermediary["merkleRoot"]!!.jsonPrimitive.content), it) }
            assertEquals(ByteVector32(intermediary["tweakedPubkey"]!!.jsonPrimitive.content), tweakedKey.value)

            val expected = it.jsonObject["expected"]!!.jsonObject
            val script = Script.write(listOf(OP_1, OP_PUSHDATA(tweakedKey.value))).byteVector()
            assertEquals(ByteVector(expected["scriptPubKey"]!!.jsonPrimitive.content), script)
            val bip350Address = Bech32.encodeWitnessAddress("bc", 1.toByte(), tweakedKey.value.toByteArray())
            assertEquals(expected["bip350Address"]!!.jsonPrimitive.content, bip350Address)
        }
    }

    private fun nullOrBytes(input: String?): ByteVector32? = when (input) {
        null, "null" -> null
        else -> ByteVector32(input)
    }

    companion object {
        data class ScriptElement(val id: Int, val script: ByteVector, val leafVersion: Int) {
            val hash: ByteVector32 = run {
                val buffer = ByteArrayOutput()
                buffer.write(leafVersion)
                BtcSerializer.writeScript(script, buffer)
                Crypto.taggedHash(buffer.toByteArray(), "TapLeaf")
            }
            companion object {
                fun fromJson(json: JsonElement): ScriptElement = ScriptElement(
                    id = json.jsonObject["id"]!!.jsonPrimitive.int,
                    script = ByteVector.fromHex(json.jsonObject["script"]!!.jsonPrimitive.content),
                    leafVersion = json.jsonObject["leafVersion"]!!.jsonPrimitive.int
                )
            }
        }

        sealed class TreeNode<T> {
            data class Leaf<T>(val value: T) : TreeNode<T>()
            data class Branch<T>(val left: TreeNode<T>, val right: TreeNode<T>) : TreeNode<T>()

            companion object {
                fun <T> read(json: JsonElement, f: (JsonElement) -> T): TreeNode<T> = when (json) {
                    is JsonObject -> Leaf(f(json))
                    is JsonArray -> Branch(read(json[0], f), read(json[1], f))
                    else -> error("unexpected $json")
                }

                fun hash(tree: TreeNode<ScriptElement>) : ByteVector32 = when(tree) {
                    is Leaf -> tree.value.hash
                    is Branch -> {
                        val h1 = hash(tree.left)
                        val h2 = hash(tree.right)
                        Crypto.taggedHash((if (LexicographicalOrdering.isLessThan(h1, h2)) h1 + h2 else h2 + h1).toByteArray(), "TapBranch")
                    }
                }
            }
        }
    }
}