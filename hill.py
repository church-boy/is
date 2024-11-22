class Hill_Cipher:
    ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    
    def gcd(self, a, b):
        if b == 0:
            return a
        else:
            return self.gcd(b, a % b)

    def transpose(self, matrix):
        return [list(row) for row in zip(*matrix)]

    def multInv(self, num, mod):
        if self.gcd(num, mod) == 1:
            for i in range(1, mod):
                if (num * i) % mod == 1:
                    return i
        return None

    def matrixMult(self, mat1, mat2, mod):
        rows_mat1 = len(mat1)
        cols_mat1 = len(mat1[0])
        cols_mat2 = len(mat2[0])
        
        resMat = [[0] * cols_mat2 for _ in range(rows_mat1)]
        
        for i in range(rows_mat1):
            for j in range(cols_mat2):
                for k in range(cols_mat1):
                    resMat[i][j] += mat1[i][k] * mat2[k][j]
                resMat[i][j] %= mod
        
        return resMat

    def strToMat(self, text, mod):
        numbers = [self.ALPHABET.index(char) for char in text if char in self.ALPHABET]
        rem = len(numbers) % mod
        while rem != 0:
            numbers.append(self.ALPHABET.index('X'))  # Append X as fillers
            rem = len(numbers) % mod
        matrix = [numbers[i:i + mod] for i in range(0, len(numbers), mod)]
        return matrix

    def matToStr(self, mat):
        return ''.join([self.ALPHABET[num] for row in mat for num in row])

    def determinant(self, matrix):
        n = len(matrix)
        if n == 1:
            return matrix[0][0]
        elif n == 2:
            return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]
        else:
            det = 0
            for j in range(n):
                sign = (-1) ** j
                minor = self.minor(matrix, 0, j)
                det += sign * matrix[0][j] * self.determinant(minor)
            return det

    def minor(self, matrix, row, col):
        return [r[:col] + r[col+1:] for r in (matrix[:row] + matrix[row+1:])]

    def cofactor_matrix(self, matrix):
        n = len(matrix)
        cofactor = [[0] * n for _ in range(n)]
        for i in range(n):
            for j in range(n):
                sign = (-1) ** (i + j)
                minor = self.minor(matrix, i, j)
                cofactor[j][i] = sign * self.determinant(minor)
        return cofactor

    def adjoint(self, matrix, mod):
        cofactor_mat = self.cofactor_matrix(matrix)
        adjoint_mat = [[cofactor_mat[i][j] % mod for j in range(len(matrix))] for i in range(len(matrix))]
        return adjoint_mat

    def scalarMult(self, scalar, mat, mod):
        return [[(scalar * mat[i][j]) % mod for j in range(len(mat[0]))] for i in range(len(mat))]

    def encrypt(self, plain_text, key_mat, mod):
        plain_mat = self.strToMat(plain_text, len(key_mat))
        encrypted_mat = self.matrixMult(key_mat, plain_mat, mod)
        encrypted_text = self.matToStr(encrypted_mat)
        return encrypted_text

    def decrypt(self, cipher_text, key_mat, mod):
        key_det = self.determinant(key_mat)
        key_inv = self.multInv(key_det, mod)
        
        if key_inv is None:
            raise ValueError("Key matrix is not invertible.")
        
        key_mat_adj = self.adjoint(key_mat, mod)
        key_mat_inv = self.scalarMult(key_inv, key_mat_adj, mod)
        
        cipher_mat = self.strToMat(cipher_text, len(key_mat))
        decrypted_mat = self.matrixMult(key_mat_inv, cipher_mat, mod)
        decrypted_text = self.matToStr(decrypted_mat)
        
        return decrypted_text

    def printMat(self, mat):
        for row in mat:
            print(' '.join(map(str, row)))

    def known_pt_ct_attack(self, plain_text, cipher_text, ord_key):
        """Perform a known plaintext-ciphertext attack to derive the key."""
        plain_text = plain_text.upper().replace(" ", "")
        cipher_text = cipher_text.upper().replace(" ", "")
        
        ptmat = self.strToMat(plain_text, ord_key)
        ctmat = self.strToMat(cipher_text, ord_key)
        
        print(f"Plain Matrix: {ptmat}")
        print(f"Cipher Matrix: {ctmat}")
        
        ptmat_transpose = self.transpose(ptmat)
        print(f"Plain Matrix Transpose: {ptmat_transpose}")
        
        ptmat_det = self.determinant(ptmat_transpose)
        ptmat_det_inv = self.multInv(ptmat_det, 26)
        
        if ptmat_det_inv is None:
            print("Plaintext matrix is not invertible.")
            return None
        
        ptmat_adj = self.adjoint(ptmat_transpose, 26)
        ptmat_inv = self.scalarMult(ptmat_det_inv, ptmat_adj, 26)
        
        print(f"Plain Matrix Inverse: {ptmat_inv}")
        
        key_mat = self.matrixMult(ctmat, ptmat_inv, 26)
        print(f"Derived Key Matrix: {key_mat}")
        
        return key_mat


# Main program
hc = Hill_Cipher()

choice = int(input("Choose operation:\n1) Encrypt\n2) Decrypt\n3) Known Plaintext-Ciphertext Attack\nEnter choice: "))
key_size = int(input("Enter key matrix size (e.g., for 2x2 matrix, enter 2): "))
ord_key = int(input("Order of Key: "))
key_mat = []
print(f"Enter {key_size}x{key_size} key matrix elements:")
for i in range(key_size):
    row = []
    for j in range(key_size):
        row.append(int(input(f"Enter element at ({i+1},{j+1}): ")))
    key_mat.append(row)

mod = 26  # Modulus for the Hill Cipher (standard for alphabet size)

if choice == 1:
    plain_text = input("Enter plaintext: ").upper().replace(" ", "")
    encrypted_text = hc.encrypt(plain_text, key_mat, mod)
    print(f"Encrypted text: {encrypted_text}")
elif choice == 2:
    cipher_text = input("Enter ciphertext: ").upper().replace(" ", "")
    try:
        decrypted_text = hc.decrypt(cipher_text, key_mat, mod)
        print(f"Decrypted text: {decrypted_text}")
    except ValueError as e:
        print(e)
elif choice == 3:
    known_plain_text = input("Enter known plaintext: ").upper().replace(" ", "")
    known_cipher_text = input("Enter corresponding known ciphertext: ").upper().replace(" ", "")
    unknown_cipher_text = input("Enter ciphertext to decrypt: ").upper().replace(" ", "")
    try:
        key_mat = hc.known_pt_ct_attack(known_plain_text, known_cipher_text, ord_key)
        if key_mat is not None:
            decrypted_text = hc.decrypt(unknown_cipher_text, key_mat, mod)
            print(f"Decrypted text using known plaintext attack: {decrypted_text}")
        else:
            print("Failed to derive key matrix.")
    except ValueError as e:
        print(e)
else:
    print("Invalid choice")
