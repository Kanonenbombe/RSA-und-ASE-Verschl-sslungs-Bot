import binascii
import discord
from discord.ext import commands
from discord.commands import Option, slash_command
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os
import io
import base64

class CryptoBot(commands.Cog):
    def __init__(self, bot):
        self.bot = bot

    async def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return public_pem, private_pem

    async def encrypt_file_with_aes(self, file_path, key):
        backend = default_backend()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
        encryptor = cipher.encryptor()

        with open(file_path, 'rb') as f:
            original_data = f.read()

        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(original_data) + padder.finalize()

        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        return iv + encrypted

    async def encrypt_file_directly_with_rsa(self, file_path, public_key_pem):
        public_key = serialization.load_pem_public_key(public_key_pem)

        with open(file_path, 'rb') as f:
            original_data = f.read()

        encrypted = public_key.encrypt(
            original_data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        encrypted_file_path = f"{file_path}.encrypted"
        with open(encrypted_file_path, 'wb') as f:
            f.write(encrypted)

        return encrypted_file_path

    async def decrypt_file_with_aes(self, encrypted_data, key):
        iv = encrypted_data[:16]
        encrypted_data = encrypted_data[16:]

        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
        decryptor = cipher.decryptor()

        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

        return decrypted_data

    async def decrypt_file_directly_with_rsa(self, encrypted_data, private_key_pem):
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
        )

        decrypted = private_key.decrypt(
            encrypted_data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return decrypted

    @slash_command(description="Verschlüsselt eine hochgeladene Datei basierend auf ihrer Größe mit RSA oder RSA und AES")
    async def encrypt(self, ctx: discord.ApplicationContext, file: Option(discord.Attachment, "Die Datei, die verschlüsselt werden soll")):
        await ctx.defer()
        public_key_pem, private_key_pem = await self.generate_rsa_keys()

        file_path = f"./temp/{file.filename}"
        await file.save(file_path)
        file_size = os.path.getsize(file_path)

        if file_size <= 32:
            encrypted_file_path = await self.encrypt_file_directly_with_rsa(file_path, public_key_pem)
            method = "RSA"
        else:
            aes_key = os.urandom(32)
            encrypted_data = await self.encrypt_file_with_aes(file_path, aes_key)

            public_key = serialization.load_pem_public_key(public_key_pem)
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            encrypted_file_path = f"{file_path}.encrypted"
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)

            method = "RSA und AES"

        try:
            if ctx.author.dm_channel is None:
                await ctx.author.create_dm()

            await ctx.author.dm_channel.send(f"Deine Datei wurde mit {method} verschlüsselt.", files=[
                discord.File(encrypted_file_path),
                discord.File(fp=io.BytesIO(public_key_pem), filename="public_key.pem"),
                discord.File(fp=io.BytesIO(private_key_pem), filename="private_key.pem"),
            ])

            if method == "RSA und AES":
                encrypted_aes_key_io = io.BytesIO(base64.b64encode(encrypted_aes_key))
                await ctx.author.dm_channel.send("Hier ist dein verschlüsselter AES-Schlüssel.", file=discord.File(fp=encrypted_aes_key_io, filename="encrypted_aes_key.txt"))

            await ctx.respond("Ich habe dir die verschlüsselte Datei und die Schlüssel per DM geschickt.")
        finally:
            os.remove(file_path)
            os.remove(encrypted_file_path)

    @slash_command(
        description="Entschlüsselt eine hochgeladene Datei mit dem privaten Schlüssel und optional mit dem AES-Schlüssel")
    async def decrypt(self, ctx: discord.ApplicationContext,
                      encrypted_file: Option(discord.Attachment, "Die verschlüsselte Datei"),
                      private_key: Option(discord.Attachment, "Der private RSA-Schlüssel"),
                      aes_key: Option(discord.Attachment, "Der AES-Schlüssel (nur wenn AES verwendet wurde)",
                                      required=False)):
        await ctx.defer()

        try:
            encrypted_file_path = f"./temp/{encrypted_file.filename}"
            await encrypted_file.save(encrypted_file_path)

            private_key_path = f"./temp/{private_key.filename}"
            await private_key.save(private_key_path)

            with open(private_key_path, 'rb') as f:
                private_key_pem = f.read()

            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()

            if aes_key:
                aes_key_path = f"./temp/{aes_key.filename}"
                await aes_key.save(aes_key_path)

                with open(aes_key_path, 'rb') as f:
                    aes_key_data = f.read()

                try:
                    encrypted_aes_key = base64.b64decode(aes_key_data)
                except binascii.Error:
                    raise ValueError(
                        "Fehlerhafte AES-Schlüsseldatei. Bitte überprüfe die Datei und versuche es erneut.")

                aes_key = await self.decrypt_file_directly_with_rsa(encrypted_aes_key, private_key_pem)
                decrypted_data = await self.decrypt_file_with_aes(encrypted_data, aes_key)
            else:
                decrypted_data = await self.decrypt_file_directly_with_rsa(encrypted_data, private_key_pem)

            decrypted_file_path = f"{encrypted_file_path}.decrypted"
            with open(decrypted_file_path, 'wb') as f:
                f.write(decrypted_data)

            try:
                if ctx.author.dm_channel is None:
                    await ctx.author.create_dm()

                await ctx.author.dm_channel.send("Hier ist deine entschlüsselte Datei.", files=[
                    discord.File(decrypted_file_path)
                ])

                await ctx.respond("Ich habe dir die entschlüsselte Datei per DM geschickt.")
            finally:
                os.remove(encrypted_file_path)
                os.remove(private_key_path)
                if aes_key:
                    os.remove(aes_key_path)
                os.remove(decrypted_file_path)

        except ValueError as e:
            await ctx.respond(f"Ein Fehler ist aufgetreten: {str(e)}")
        except Exception as e:
            await ctx.respond(
                f"Entschlüsselung fehlgeschlagen. Bitte überprüfe die hochgeladenen Dateien. Technischer Fehler: {str(e)}")


def setup(bot):
    bot.add_cog(CryptoBot(bot))
