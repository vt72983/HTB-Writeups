from pwn import *

HOST = "1.1.1.1"
PORT = 0000

conn = remote(HOST, PORT)
reconstructed_bit_pairs = []

def recv_line_stripped():
    return conn.recvline().decode(errors='ignore').strip()

try:
    while True:
        conn.recvuntil(b"Basis : ")
        basis = recv_line_stripped()

        m0_line = recv_line_stripped()
        m1_line = recv_line_stripped()
        m0 = int(m0_line.split()[-1])
        m1 = int(m1_line.split()[-1])

        if m0 == 0 and m1 == 0:
            instructions = "Z:2;Z:2"
        elif m0 == 1 and m1 == 0:
            instructions = "Z:2"
        elif m0 == 0 and m1 == 1:
            instructions = "X:2"
        elif m0 == 1 and m1 == 1:
            instructions = "Z:2;X:2"
        else:
            instructions = "Z:2;Z:2"

        conn.sendlineafter(b"Specify the instructions : ", instructions.encode())
        conn.sendlineafter(b"Specify the measurement basis : ", basis.encode())

        res_line = recv_line_stripped()
        final_measurement = int(res_line.split()[-1])

        first_bit = '0' if basis == 'Z' else '1'
        reconstructed_bit_pairs.append(first_bit + str(final_measurement))

except EOFError:
    binary_string = ''.join(reconstructed_bit_pairs)
    if binary_string:
        n = int(binary_string, 2)
        flag_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        try:
            flag = flag_bytes.decode()
        except:
            flag = flag_bytes
        print('FLAG:', flag)
finally:
    conn.close()
