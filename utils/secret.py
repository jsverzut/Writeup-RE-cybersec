with open("buffer.bin", "rb") as file:
    data = file.read()

buffer = bytearray(33)
for i in range(33):
    buffer[i] = data[i] ^ data[i+33]

print(bytes(buffer))
