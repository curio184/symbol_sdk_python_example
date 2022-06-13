import datetime
import json
import time
from binascii import hexlify, unhexlify
from pathlib import Path
from typing import List

import requests
import sha3
from symbolchain.CryptoTypes import PrivateKey, PublicKey
from symbolchain.facade.SymbolFacade import SymbolFacade
from symbolchain.PrivateKeyStorage import PrivateKeyStorage
from symbolchain.sc import (AggregateCompleteTransaction, Amount,
                            BlockDuration, EmbeddedMosaicMetadataTransaction,
                            EmbeddedTransferTransaction,
                            MosaicDefinitionTransaction, MosaicFlags,
                            MosaicMetadataTransaction, MosaicNonce,
                            MosaicSupplyChangeAction,
                            MosaicSupplyChangeTransaction, TransferTransaction)
from symbolchain.symbol.KeyPair import KeyPair
from symbolchain.symbol.Network import Address


class NonceGenerator():

    @staticmethod
    def generate() -> int:
        """
        ナンスを生成する
        """
        return int(time.mktime(datetime.datetime.now().timetuple()))


class AccountConfig:

    @staticmethod
    def load_pem(pem_file_path: str, password: str = None) -> KeyPair:
        """
        アカウント情報を*.pemファイルに保存する
        """
        file = Path(pem_file_path)
        storage = PrivateKeyStorage(file.parent, password)
        return KeyPair(storage.load(file.stem))

    @staticmethod
    def save_pem(pem_file_path: str, raw_private_key: str, password: str = None):
        """
        アカウント情報を*.pemファイルから読み込む
        """
        file = Path(pem_file_path)
        private_key = PrivateKey(unhexlify(raw_private_key))
        storage = PrivateKeyStorage(file.parent, password)
        storage.save(file.stem, private_key)

    def public_key_to_addres(facade: SymbolFacade, public_key: PublicKey) -> Address:
        """
        Public KeyをAddressに変換する
        """
        return facade.network.public_key_to_address(public_key)


class KeyGenerator:

    @staticmethod
    def generate_uint64_key(input: str) -> int:
        # 下記コマンドと互換
        # $ symbol-cli converter stringToKey -v header
        # AD6D8491D21180E5D
        hasher = sha3.sha3_256()
        hasher.update(input.encode())
        digest = hasher.digest()
        result = int.from_bytes(digest[0:8], "little")
        return result


class CatapultRESTAPI:

    def __init__(self, node_url: str) -> None:
        self._node_url = node_url

    def get_epoch_adjustment(self) -> int:
        """
        epochAdjustmentを取得する
        """
        url = self._node_url + "/network/properties"
        response = requests.get(url)
        if response.status_code != 200:
            raise Exception("status code is {}".format(response.status_code))
        contents = json.loads(response.text)
        epoch_adjustment = int(contents["network"]["epochAdjustment"].replace("s", ""))
        return epoch_adjustment

    def get_currency_mosaic_id(self) -> int:
        """
        currencyMosaicIdを取得する
        """
        url = self._node_url + "/network/properties"
        response = requests.get(url)
        if response.status_code != 200:
            raise Exception("status code is {}".format(response.status_code))
        contents = json.loads(response.text)
        currency_mosaic_id = int(contents["chain"]["currencyMosaicId"].replace("'", ""), 16)
        return currency_mosaic_id


class SymbolTransactionCreator:

    def __init__(self, network_name: str, node_url: str, epoch_adjustment: int, max_fee: int, expiration_hour: int) -> None:
        self._facade = SymbolFacade(network_name)
        self._node_url = node_url
        self._epoch_adjustment = epoch_adjustment
        self._max_fee = Amount(max_fee)
        self._expiration_hour = expiration_hour
        if network_name == "mainnet":
            self._explorer_url = "https://symbol.fyi/transactions/"
        elif network_name == "testnet":
            self._explorer_url = "https://testnet.symbol.fyi/transactions/"
        else:
            raise Exception("Unknown network name.")

    def _get_deadline(self):
        deadline = (int((datetime.datetime.today() + datetime.timedelta(hours=self._expiration_hour)
                         ).timestamp()) - self._epoch_adjustment) * 1000
        return deadline

    def create_transfer_transaction(
        self,
        signer_public_key: PublicKey,
        recipient_address: Address,
        mosaics: List[dict],
        message: str
    ) -> TransferTransaction:
        """
        転送トランザクションを作成する
        """

        deadline = self._get_deadline()

        tx: TransferTransaction = self._facade.transaction_factory.create({
            "type": "transfer_transaction",
            "signer_public_key": signer_public_key,
            "deadline": deadline,
            "fee": self._max_fee,
            "recipient_address": recipient_address,
            "mosaics": mosaics,
            # NOTE: additional 0 byte at the beginning is added for compatibility with explorer
            # and other tools that treat messages starting with 00 byte as "plain text"
            "message": bytes(1) + message.encode("utf8")
        })

        return tx

    def create_aggregate_transfer_transaction(
        self,
        signer_public_key: PublicKey,
        recipient_address: Address,
        mosaics: List[dict],
        messages: List[str]
    ) -> AggregateCompleteTransaction:
        """
        アグリゲートトランザクションを作成する
        https://docs.symbol.dev/guides/aggregate/sending-multiple-transactions-together-with-aggregate-complete-transaction.html
        """

        deadline = self._get_deadline()

        # インナートランザクションを作成する
        inner_txs: List[EmbeddedTransferTransaction] = []
        for message in messages:
            inner_tx: EmbeddedTransferTransaction = self._facade.transaction_factory.create_embedded({
                "type": "transfer_transaction",
                "signer_public_key": signer_public_key,
                "recipient_address": recipient_address,
                "mosaics": mosaics,
                # NOTE: additional 0 byte at the beginning is added for compatibility with explorer
                # and other tools that treat messages starting with 00 byte as "plain text"
                "message": bytes(1) + message.encode("utf8")
            })
            inner_txs.append(inner_tx)

        # アグリゲートトランザクションを作成する
        aggre_tx: AggregateCompleteTransaction = self._facade.transaction_factory.create({
            "type": "aggregate_complete_transaction",
            "signer_public_key": signer_public_key,
            "fee": self._max_fee,
            "deadline": deadline,
            "transactions_hash":  self._facade.hash_embedded_transactions(inner_txs),
            "transactions": inner_txs
        })

        return aggre_tx

    def create_mosaic_definition_transaction(
            self,
            signer_public_key: PublicKey,
            divisibility: int,
            duration: int,
            transferable: bool = False,
            supply_mutable: bool = False,
            restrictable: bool = False,
            revokable: bool = False
    ) -> MosaicDefinitionTransaction:
        """
        モザイクのプロパティを定義する
        https://docs.symbol.dev/ja/guides/mosaic/creating-a-mosaic.html

        下記は一連をアグリゲートトランザクションで作成するのが一般的かも
        ・MosaicDefinitionTransaction
        ・MosaicSupplyChangeTransaction
        """

        deadline = self._get_deadline()

        flags = MosaicFlags.NONE
        flags = flags | MosaicFlags.TRANSFERABLE if transferable else flags
        flags = flags | MosaicFlags.SUPPLY_MUTABLE if supply_mutable else flags
        flags = flags | MosaicFlags.RESTRICTABLE if restrictable else flags
        flags = flags | MosaicFlags.REVOKABLE if revokable else flags

        tx: MosaicDefinitionTransaction = self._facade.transaction_factory.create({
            "type": "mosaic_definition_transaction",
            "signer_public_key": signer_public_key,
            "deadline": deadline,
            "fee": self._max_fee,
            "duration": BlockDuration(duration),
            "nonce": MosaicNonce(NonceGenerator.generate()),
            "flags": flags,
            "divisibility": divisibility
        })

        return tx

    def create_mosaic_supply_change_transaction(
        self,
        signer_public_key: PublicKey,
        mosaic_id: int,
        supply_units: int,
    ) -> MosaicSupplyChangeTransaction:
        """
        モザイクの供給量を変更する
        https://docs.symbol.dev/ja/guides/mosaic/modifying-mosaic-supply.html

        16進数表記のmosaic_idは10進数に変換して指定する
        > mosaic_id = 0x72619171D5D975B9
        > mosaic_id = int("72619171D5D975B9", 16)
        """

        deadline = self._get_deadline()

        tx: MosaicSupplyChangeTransaction = self._facade.transaction_factory.create({
            "type": "mosaic_supply_change_transaction",
            "signer_public_key": signer_public_key,
            "deadline": deadline,
            "fee":  self._max_fee,
            "mosaic_id": mosaic_id,
            "delta": Amount(supply_units),
            "action": MosaicSupplyChangeAction.INCREASE
        })

        return tx

    def create_mosaic_metadata_transaction(
        self,
        signer_public_key: PublicKey,
        target_address: Address,
        target_mosaic_id: int,
        scoped_metadata_key: str,
        value: str
    ) -> MosaicMetadataTransaction:
        """
        モザイクへのメタデータの割り当て
        https://docs.symbol.dev/guides/metadata/assigning-metadata-entries-to-a-mosaic.html

        下記コマンドと同等
        $ symbol-cli converter stringToKey -v header
        AD6D8491D21180E5
        $ symbol-cli transaction mosaicmetadata --max-fee 2000000 --mode normal --mosaic-id 251208ED3D0ABC84 --target-address TBCSXNJ6FTO2BQUAI7ZOIGVQKOARQ7ADKLSKIRI --key AD6D8491D21180E5 --value transactionhash
        """

        deadline = self._get_deadline()

        # MetadataTransactionはInnerTransactionが1つの場合でもAggregateTransactionにする必要がある。
        # AggregateTransactionにしない場合、リクエスト自体は202で受け付けられるが、反映されることはなかった。
        # Desktop Wallet、CLIでも操作しても必ずAggregateTransactionになるので、そういう仕様かも。

        # インナートランザクションを作成する
        tx: EmbeddedMosaicMetadataTransaction = self._facade.transaction_factory.create_embedded({
            "type": "mosaic_metadata_transaction",
            "signer_public_key": signer_public_key,
            "target_address": target_address,
            "target_mosaic_id": target_mosaic_id,
            "scoped_metadata_key": KeyGenerator.generate_uint64_key(scoped_metadata_key),
            "value": bytes(1) + value.encode("utf8"),
            "value_size_delta": len(bytes(1) + value.encode("utf8"))
        })

        # アグリゲートトランザクションを作成する
        aggre_tx: AggregateCompleteTransaction = self._facade.transaction_factory.create({
            "type": "aggregate_complete_transaction",
            "signer_public_key": signer_public_key,
            "fee": self._max_fee,
            "deadline": deadline,
            "transactions_hash":  self._facade.hash_embedded_transactions([tx]),
            "transactions": [tx]
        })

        return aggre_tx

    def sign_and_announce_transaction(self, transaction, key_pair: KeyPair) -> str:
        """
        トランザクションを署名し、ノードにアナウンスする

        トランザクションが反映されないときのチェックリスト
        ・status_code == 202だから成功とは限らない
        ・EpochAdjustmentは正しいか？
        ・CurrencyMosaicIDは正しいか？
        ・Feeは低すぎないか？
        ・AggregateTransactionの場合
            インナートランザクションのcreateにcreate_embedded()を使用しているか？
            インナートランザクションの型はEmbeded***Transactionとなっているか？
        """

        # トランザクションを署名する
        signature = self._facade.sign_transaction(key_pair, transaction)

        # ノードにアナウンスする
        url = self._node_url + "/transactions"
        http_headers = {"Content-type": "application/json"}
        payload = self._facade.transaction_factory.attach_signature(transaction, signature).encode()
        tx_hash = self._facade.hash_transaction(transaction)
        response = requests.put(url, headers=http_headers, data=payload)
        if response.status_code != 202:
            raise Exception("status code is {}".format(response.status_code))

        print("tx hash:" + str(tx_hash))
        print("status code:" + str(response.status_code))
        print(self._explorer_url + str(tx_hash))

        return str(tx_hash)


if __name__ == "__main__":

    # ネットワーク情報
    network_name = "testnet"
    node_url = "https://node3.xym-harvesting.com:3001"
    catapult_api = CatapultRESTAPI(node_url)
    epoch_adjustment = catapult_api.get_epoch_adjustment()      # 1637848847
    currency_mosaic_id = catapult_api.get_currency_mosaic_id()  # symbol.xym, 0x3A8416DB2D53B6C8

    # トランザクション設定
    expiration_hour = 2
    max_fee = 2000000

    # アカウント情報(送信元および発行者)
    facade = SymbolFacade(network_name)
    # AccountConfig.save_pem("./configs/private_key.pem", "PRIVATE_KEY", "PASSWORD")
    sender_key_pair = AccountConfig.load_pem("./configs/private_key.pem", "PASSWORD")
    sender_public_key = sender_key_pair.public_key
    sender_private_key = sender_key_pair.private_key
    sender_address = AccountConfig.public_key_to_addres(facade, sender_public_key)

    # アカウント情報(送信先)
    recipient_address = Address("TA3HQR6NPMXK7W6EP3AO6X5S4OSHVBU3ZEWBTNQ")

    creator = SymbolTransactionCreator(
        network_name, node_url, epoch_adjustment, max_fee, expiration_hour
    )

    # ↓ 試したいものをアンコメント

    # 転送トランザクションを作成する
    # mosaics = [{"mosaic_id": currency_mosaic_id, "amount": int(18 * 1000000)}]
    # tx = creator.create_transfer_transaction(
    #     sender_public_key, recipient_address, mosaics, "hello symbol"
    # )
    # creator.sign_and_announce_transaction(tx, sender_key_pair)

    # アグリゲートトランザクションを作成する
    # mosaics = [{"mosaic_id": currency_mosaic_id, "amount": int(0 * 1000000)}]
    # tx = creator.create_aggregate_transfer_transaction(
    #     sender_public_key, recipient_address, mosaics, ["inner transaction 1", "inner transaction 2"]
    # )
    # creator.sign_and_announce_transaction(tx, sender_key_pair)

    # モザイクのプロパティを定義する
    # tx = creator.create_mosaic_definition_transaction(
    #     sender_public_key, 0, 1000, True, False, False, False
    # )
    # creator.sign_and_announce_transaction(tx, sender_key_pair)

    # モザイクの供給量を変更する
    # tx = creator.create_mosaic_supply_change_transaction(
    #     sender_public_key, 0x251208ED3D0ABC84, 1000
    # )
    # creator.sign_and_announce_transaction(tx, sender_key_pair)

    # モザイクへのメタデータの割り当て
    # tx = creator.create_mosaic_metadata_transaction(
    #     sender_public_key, sender_address, 0x251208ED3D0ABC84, "metadata key", "metadata value"
    # )
    # creator.sign_and_announce_transaction(tx, sender_key_pair)
