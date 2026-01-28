from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

password = "radu2022"  # parola dorita
password = password[:72]  # IMPORTANT pentru bcrypt

hashed = pwd_context.hash(password)
print("Hash generat:", hashed)