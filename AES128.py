

# An internal class which contains some basic helper methods
class Tools:

    # XOR 2 lists into a single list
    @staticmethod
    def xor_lists(list_1, list_2):
        res_list = []
        size_list = min(len(list_1), len(list_2))
        for j in range(0, size_list):
            res_list.append(list_1[j] ^ list_2[j])
        return res_list

    # Circularly shift a list to the left with the specified number of positions
    @staticmethod
    def circular_shift_list_left(elem_list, shift=1):
        res_list = []
        res_list.extend(elem_list[shift:])
        res_list.extend(elem_list[0:shift])
        return res_list

    # Circularly shift a list to the right with the specified number of positions
    @staticmethod
    def circular_shift_list_right(elem_list, shift=1):
        res_list = []
        limit = len(elem_list) - shift
        res_list.extend(elem_list[limit:len(elem_list)])
        res_list.extend(elem_list[0:limit])
        return res_list

    # Determines the decimal indexes from the ascii code in HEX
    @staticmethod
    def hexify(character_ascii_code):
        ascii_hex = hex(character_ascii_code)
        first = 0;
        second = 0;
        if ascii_hex != "0x0":
            if len(ascii_hex) > 3:
                first = int(ascii_hex[2], 16)
                second = int(ascii_hex[3], 16)
            else:
                if len(ascii_hex) > 2:
                    second = int(ascii_hex[2], 16)
        return first, second

    # Transpose a linearly stored array
    @staticmethod
    def transpose_linear_array(matrix_array, nb_lines, nb_cols):
        transposed_array = []
        i = 0
        j = 0
        k = 0
        matrix_nb_elems = nb_lines * nb_cols
        while j < matrix_nb_elems:
            if i >= matrix_nb_elems:
                k = k + 1
                i = k
            j += 1
            transposed_array.append(matrix_array[i])
            i += nb_cols
        return transposed_array

    # Galois multiplication of two 8 bit characters x and y
    @staticmethod
    def galois_product(x, y):
        p = 0
        for counter in range(0, 8):
            if y & 1:
                p ^= x
            hi_bit_set = x & 0x80
            x <<= 1

            x &= 0xFF                   # keep a 8 bit
            if hi_bit_set:
                x ^= 0x1b

            y >>= 1
        return p


# A class for performing a 128 bit AES encryption for the specified string
class AES128:

    # Round key table (1 -> 108)
    _RCON_TUPLE = (0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c)

    # Static SBox table for encryption
    _SBOX_BYTE_ENC_TUPLE = (0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
                            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
                            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
                            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
                            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
                            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
                            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
                            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
                            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
                            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
                            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
                            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
                            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
                            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
                            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
                            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16)

    # Static SBox table for decryption
    _SBOX_BYTE_DEC_TUPLE = (0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
                            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
                            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
                            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
                            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
                            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
                            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
                            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
                            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
                            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
                            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
                            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
                            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
                            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
                            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
                            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D)

    # Static mix columns encryption matrix
    _MIX_COLS_ENC_MATRIX = [0x02, 0x03, 0x01, 0x01,
                            0x01, 0x02, 0x03, 0x01,
                            0x01, 0x01, 0x02, 0x03,
                            0x03, 0x01, 0x01, 0x02]

    # Static mix column decryption matrix
    _MIX_COLS_DEC_MATRIX = [0x0E, 0x0B, 0x0D, 0x09,
                            0x09, 0x0E, 0x0B, 0x0D,
                            0x0D, 0x09, 0x0E, 0x0B,
                            0x0B, 0x0D, 0x09, 0x0E]

    # The standard block matrix size
    _MATRIX_SIZE = 4

    # Construct the object (the clear text is kept column-wise)
    def __init__(self, data_string, encryption_key):
        my_data = data_string
        my_key = encryption_key

        # Make sure the data and key are 128 bit aligned
        while len(my_data) % 16 != 0:
            my_data += chr(0x00)
        while len(my_key) % 16 != 0:
            my_key += chr(0x00)

        # self.clear_text = Tools.transpose_linear_array(my_data, AES128._MATRIX_SIZE, AES128._MATRIX_SIZE)
        self.clear_text = my_data
        self.key = my_key
        self.state = [ord(c) for c in self.clear_text]
        self.round_key = []

    # Run the encryption sequence for the stored data and key
    def run_encryption(self):

        print("Encrypting contents...")

        # Precompute the round keys (key expansion)
        self._compute_round_keys()
        # self.print_round_keys()

        # Add initial round key to the state matrix
        self._add_round_key(0)
        self.print_state("Initial state matrix")

        # Now start doing some actual heavy lifting for rounds 1->9
        for i in range(1, 10):
            self._sub_bytes(0)
            self._shift_row()
            self._mix_cols(0)
            self._add_round_key(i)
            self.print_state("State matrix after stage [" + str(i) + "]")

        # Special case 10th round (no mix columns)
        self._sub_bytes(0)
        self._shift_row()
        self._add_round_key(10)
        self.print_state("State matrix after stage [" + str(10) + "] <special round>")

        # The final value after encryption
        self.print_state("Sequence value after encryption")

    # Run the decryption sequence for the stored data and key
    def run_decryption(self):

        print("Decrypting contents...")

        # Precompute the round keys (key expansion)
        self._compute_round_keys()
        # self.print_round_keys()

        # Add initial round key to the state matrix
        self._add_round_key(10)
        self.print_state("Initial state matrix")

        # Now start doing some actual heavy lifting for rounds 1->9
        for i in reversed(range(1, 10)):
            self._shift_row(1)
            self._sub_bytes(1)
            self._add_round_key(i)
            self._mix_cols(1)
            self.print_state("State matrix after stage [" + str(i) + "]")

        # Special case 10th round (no mix columns)
        self._shift_row(1)
        self._sub_bytes(1)
        self._add_round_key(0)
        self.print_state("State matrix after stage [" + str(0) + "] <special round>")

        # The final value after encryption
        self.print_state("Sequence value after decryption")

    # Get the final result
    def get_result(self):
        result = [chr(c) for c in self.state]
        return result

    # Print the current state
    def print_state(self, msg="Current state:"):
        print(msg)
        for j in self.state:
            print(hex(j), end="; ")
        print("\n")

    # Print the round keys
    def print_round_keys(self, msg="Round keys:"):
        print(msg)
        for r_key in self.round_key:
            for j in r_key:
                print(hex(j), end="; ")
            print("\n")

    # Compute round keys (perform the key expansion)
    def _compute_round_keys(self):

        # round 0 key generation (same as the initial key)
        key_ints = [ord(c) for c in self.key]
        round_key = key_ints
        self.round_key.append(round_key)

        # round 1 -> 10 key generation
        for round_nb in range(1, 11):
            last_key = self.round_key[len(self.round_key) - 1]
            word_0 = last_key[0:4]
            word_1 = last_key[4:8]
            word_2 = last_key[8:12]
            word_3 = last_key[12:16]

            word_4_n = Tools.xor_lists(word_0, AES128._g_op(word_3, round_nb))
            word_5_n = Tools.xor_lists(word_4_n, word_1)
            word_6_n = Tools.xor_lists(word_5_n, word_2)
            word_7_n = Tools.xor_lists(word_6_n, word_3)
            round_key = word_4_n + word_5_n + word_6_n + word_7_n

            self.round_key.append(round_key)

    # Add the Round Key transformation to the current state matrix
    def _add_round_key(self, round_nb):
        ret_list = Tools.xor_lists(self.state, self.round_key[round_nb])
        self.state = ret_list

    # Apply a Substitution bytes transformation to the current state matrix
    def _sub_bytes(self, decrypt=0):
        ret_list = AES128._get_sboxed_list(self.state, decrypt)
        self.state = ret_list

    # Apply a Shift row transformation to the current state matrix
    def _shift_row(self, decrypt=0):
        transposed_state = Tools.transpose_linear_array(self.state, AES128._MATRIX_SIZE, AES128._MATRIX_SIZE)

        if decrypt != 0:
            ret_list = Tools.circular_shift_list_right(transposed_state[0:4], 0)
            ret_list.extend(Tools.circular_shift_list_right(transposed_state[4:8], 1))
            ret_list.extend(Tools.circular_shift_list_right(transposed_state[8:12], 2))
            ret_list.extend(Tools.circular_shift_list_right(transposed_state[12:16], 3))
        else:
            ret_list = Tools.circular_shift_list_left(transposed_state[0:4], 0)
            ret_list.extend(Tools.circular_shift_list_left(transposed_state[4:8], 1))
            ret_list.extend(Tools.circular_shift_list_left(transposed_state[8:12], 2))
            ret_list.extend(Tools.circular_shift_list_left(transposed_state[12:16], 3))
        self.state = Tools.transpose_linear_array(ret_list, AES128._MATRIX_SIZE, AES128._MATRIX_SIZE)

    # Apply a Mix columns transformation to the current state matrix
    def _mix_cols(self, decrypt=0):
        res_list = [0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0,
                    0, 0, 0, 0]
        transposed_state = Tools.transpose_linear_array(self.state, AES128._MATRIX_SIZE, AES128._MATRIX_SIZE)
        galois_product = 0
        for i in range(0, AES128._MATRIX_SIZE):
            for j in range(0, AES128._MATRIX_SIZE):
                for k in range(0, AES128._MATRIX_SIZE):
                    if decrypt != 0:
                        galois_product = Tools.galois_product(AES128._MIX_COLS_DEC_MATRIX[i * AES128._MATRIX_SIZE + k],
                                                              transposed_state[k * AES128._MATRIX_SIZE + j])
                    else:
                        galois_product = Tools.galois_product(AES128._MIX_COLS_ENC_MATRIX[i * AES128._MATRIX_SIZE + k],
                                                              transposed_state[k * AES128._MATRIX_SIZE + j])
                    res_list[i * AES128._MATRIX_SIZE + j] = res_list[i * AES128._MATRIX_SIZE + j] ^ galois_product
        self.state = Tools.transpose_linear_array(res_list, AES128._MATRIX_SIZE, AES128._MATRIX_SIZE)

    # Get the a list of sboxed values for the specified string
    @staticmethod
    def _get_sboxed_list(ascii_codes_string, decrypt=0):
        s_boxed_list = []
        my_tuple = (0, 0)
        for clear_character in ascii_codes_string:
            my_tuple = Tools.hexify(clear_character)
            if decrypt != 0:
                s_boxed_list.append(AES128._SBOX_BYTE_DEC_TUPLE[16 * my_tuple[0] + my_tuple[1]])
            else:
                s_boxed_list.append(AES128._SBOX_BYTE_ENC_TUPLE[16 * my_tuple[0] + my_tuple[1]])
        return s_boxed_list

    # Determine the round key for the w3 word on the specified round stage
    @staticmethod
    def _g_op(list_elem, stage_round):
        rcon = [AES128._RCON_TUPLE[stage_round], 0x00, 0x00, 0x00]
        shifted_list = Tools.circular_shift_list_left(list_elem, 1)
        s_boxed_list = AES128._get_sboxed_list(shifted_list)
        res_list = Tools.xor_lists(s_boxed_list, rcon)
        return res_list