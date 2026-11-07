import random
import time
import hashlib
import os

# =====================================================================
# MODULE 1: CÁC HÀM TOÁN HỌC NỀN TẢNG (TỰ CÀI ĐẶT TỪ ĐẦU)
# =====================================================================

def gcd(a: int, b: int) -> int:
    """Tìm ước chung lớn nhất của a và b bằng thuật toán Euclid."""
    while b != 0:
        a, b = b, a % b
    return a

def extended_gcd(a: int, b: int):
    """
    Thuật toán Euclid mở rộng: Tìm (g, x, y) sao cho a*x + b*y = g = gcd(a, b).
    """
    if b == 0:
        return a, 1, 0
    else:
        g, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return g, x, y

def mod_inverse(r: int, q: int) -> int:
    """Tìm phần tử nghịch đảo r^(-1) mod q sao cho (r * r_inv) % q == 1."""
    g, x, _ = extended_gcd(r, q)
    if g != 1:
        raise ValueError(f"Không tồn tại nghịch đảo modulo vì gcd({r}, {q}) = {g} != 1")
    return x % q

def is_superincreasing(W: list) -> bool:
    """Kiểm tra xem danh sách W có phải là dãy siêu tăng hay không."""
    current_sum = 0
    for w in W:
        if w <= current_sum:
            return False
        current_sum += w
    return True


# =====================================================================
# MODULE 2: LÕI HỆ MÃ BA LÔ MERKLE-HELLMAN (MHK)
# =====================================================================

class MerkleHellmanKnapsack:
    def __init__(self, W=None, q=None, r=None, bit_length=64):
        """
        Nếu truyền W, q, r vào -> Chế độ thu nhỏ (Tiny Mode) để chạy ví dụ tính tay.
        Nếu để trống -> Chế độ đầy đủ (Full Mode) tự động sinh khóa ngẫu nhiên.
        """
        if W is not None and q is not None and r is not None:
            if not is_superincreasing(W):
                raise ValueError("Dãy W truyền vào không phải là dãy siêu tăng!")
            if q <= sum(W):
                raise ValueError("Modulo q phải lớn hơn tổng các phần tử của W!")
            if gcd(r, q) != 1:
                raise ValueError("Số nhân r và modulo q phải nguyên tố cùng nhau!")
            self.W = W
            self.q = q
            self.r = r
            self.n = len(W)
        else:
            self.n = bit_length
            self.W, self.q, self.r = self._generate_random_private_key(bit_length)

        # Tính sẵn nghịch đảo modulo r^(-1) mod q và khóa công khai B
        self.r_inv = mod_inverse(self.r, self.q)
        self.B = [(self.r * w) % self.q for w in self.W]

    def _generate_random_private_key(self, n: int):
        """Tự động sinh khóa riêng (W, q, r) cho phiên bản đầy đủ."""
        W = []
        current_sum = 0
        for _ in range(n):
            # Phần tử tiếp theo lớn hơn tổng các phần tử trước một khoảng ngẫu nhiên
            next_w = current_sum + random.randint(1, 50)
            W.append(next_w)
            current_sum += next_w

        q = current_sum + random.randint(10, 1000)
        while True:
            r = random.randint(2, q - 1)
            if gcd(r, q) == 1:
                break
        return W, q, r

    def encrypt_block(self, bits: list, verbose: bool = False) -> int:
        """Mã hóa 1 khối n bit thành 1 số nguyên C."""
        if len(bits) != self.n:
            raise ValueError(f"Khối bit phải có độ dài đúng bằng {self.n}")
        
        C = sum(bit * b for bit, b in zip(bits, self.B))
        
        if verbose:
            terms = [f"{bit}*{b}" for bit, b in zip(bits, self.B) if bit == 1]
            print(f"  [+] Bản rõ dạng bit : {bits}")
            print(f"  [+] Khóa công khai B: {self.B}")
            print(f"  [+] Tính bản mã C   : {' + '.join(terms)} = {C}")
        return C

    def decrypt_block(self, C: int, verbose: bool = False) -> list:
        """Giải mã số nguyên C về lại khối n bit bằng thuật toán tham lam."""
        S_prime = (C * self.r_inv) % self.q
        
        if verbose:
            print(f"  [+] Nghịch đảo r^-1 : {self.r}^(-1) mod {self.q} = {self.r_inv}")
            print(f"  [+] Quy đổi tổng S' : ({C} * {self.r_inv}) mod {self.q} = {S_prime}")
            print("  [+] Bảng giải ba lô siêu tăng (duyệt ngược từ cuối về đầu):")
            print(f"      {'Bước':<6} | {'w_i':<6} | {'S_prime':<8} | {'So sánh':<12} | {'Bit x_i':<7} | {'S_prime mới'}")
            print("      " + "-" * 62)

        bits = [0] * self.n
        # Duyệt ngược từ phần tử cuối cùng (n-1) về 0
        for i in range(self.n - 1, -1, -1):
            w_i = self.W[i]
            old_S = S_prime
            if S_prime >= w_i:
                bits[i] = 1
                S_prime -= w_i
                comp_str = f"{old_S} >= {w_i}"
            else:
                bits[i] = 0
                comp_str = f"{old_S} < {w_i}"
            
            if verbose:
                print(f"      i={i+1:<4} | {w_i:<6} | {old_S:<8} | {comp_str:<12} | x_{i+1}={bits[i]:<3} | {S_prime}")

        return bits


# =====================================================================
# MODULE 3: XỬ LÝ CHUỖI VĂN BẢN VÀ FILE THỰC TẾ (CÓ PADDING)
# =====================================================================

def bytes_to_bit_blocks(data: bytes, block_size: int) -> list:
    """
    Chuyển mảng bytes sang các khối bit có độ dài block_size.
    Sử dụng kỹ thuật Padding chuẩn: thêm bit 1 và các bit 0 ở cuối để không mất dữ liệu.
    """
    bit_stream = []
    for byte in data:
        # Chuyển mỗi byte thành 8 bit
        for i in range(7, -1, -1):
            bit_stream.append((byte >> i) & 1)
    
    # Đánh dấu kết thúc dữ liệu thật bằng một bit 1, sau đó điền bit 0 cho tròn khối
    bit_stream.append(1)
    while len(bit_stream) % block_size != 0:
        bit_stream.append(0)
        
    # Chia thành từng khối có kích thước block_size
    blocks = [bit_stream[i:i + block_size] for i in range(0, len(bit_stream), block_size)]
    return blocks

def bit_blocks_to_bytes(blocks: list) -> bytes:
    """Khôi phục lại mảng bytes gốc từ các khối bit và gỡ bỏ phần padding."""
    bit_stream = [bit for block in blocks for bit in block]
    
    # Tìm bit 1 cuối cùng (vị trí đánh dấu padding) và cắt bỏ từ đó trở về sau
    while bit_stream and bit_stream[-1] == 0:
        bit_stream.pop()
    if bit_stream and bit_stream[-1] == 1:
        bit_stream.pop()
        
    # Gom lại từng cụm 8 bit thành 1 byte
    byte_array = bytearray()
    for i in range(0, len(bit_stream), 8):
        byte_val = 0
        for bit in bit_stream[i:i+8]:
            byte_val = (byte_val << 1) | bit
        byte_array.append(byte_val)
    return bytes(byte_array)


# =====================================================================
# MODULE 4: CHẠY DEMO & BỘ KIỂM THỬ (TEST CASES)
# =====================================================================

def run_all_demos():
    print("=" * 75)
    print("CA KIỂM THỬ 1: PHIÊN BẢN THU NHỎ (ĐỐI CHIẾU 100% VỚI VÍ DỤ TÍNH TAY)")
    print("=" * 75)
    W_tiny = [2, 3, 7, 14, 30, 57, 120, 250]
    q_tiny = 491
    r_tiny = 41
    mhk_tiny = MerkleHellmanKnapsack(W=W_tiny, q=q_tiny, r=r_tiny)

    # Ký tự 'A' -> ASCII 65 -> Nhị phân 01000001
    char_A_bits = [0, 1, 0, 0, 0, 0, 0, 1]
    print(f"[*] Bản rõ đầu vào: Ký tự 'A' -> Khối bit: {char_A_bits}")
    
    print("\n--- QUÁ TRÌNH MÃ HÓA ---")
    C_tiny = mhk_tiny.encrypt_block(char_A_bits, verbose=True)
    
    print("\n--- QUÁ TRÌNH GIẢI MÃ ---")
    decrypted_bits = mhk_tiny.decrypt_block(C_tiny, verbose=True)
    print(f"\n[*] Khối bit sau giải mã: {decrypted_bits}")
    assert decrypted_bits == char_A_bits, "Lỗi: Giải mã không khớp!"
    print("[✓] KẾT QUẢ: Khớp tuyệt đối với bảng tính tay (C = 553, S' = 253)!\n")

    print("=" * 75)
    print("CA KIỂM THỬ 2: MÃ HÓA VĂN BẢN TIẾNG VIỆT VỚI KHÓA ĐẦY ĐỦ 64-BIT")
    print("=" * 75)
    mhk_full = MerkleHellmanKnapsack(bit_length=64)
    text_msg = "An toàn và bảo mật thông tin - Hệ mã ba lô Merkle-Hellman!"
    print(f"[*] Bản rõ gốc       : {text_msg}")
    
    data_bytes = text_msg.encode('utf-8')
    blocks = bytes_to_bit_blocks(data_bytes, mhk_full.n)
    ciphertexts = [mhk_full.encrypt_block(b) for b in blocks]
    print(f"[*] Số khối 64-bit   : {len(blocks)} khối")
    print(f"[*] Bản mã thu được  : {ciphertexts[:2]} ... (hiển thị 2 khối đầu)")
    
    dec_blocks = [mhk_full.decrypt_block(c) for c in ciphertexts]
    recovered_text = bit_blocks_to_bytes(dec_blocks).decode('utf-8')
    print(f"[*] Bản rõ khôi phục : {recovered_text}")
    assert recovered_text == text_msg
    print("[✓] KẾT QUẢ: Giải mã chuỗi tiếng UTF-8 chính xác 100%!\n")

    print("=" * 75)
    print("CA KIỂM THỬ 3: MÃ HÓA DỮ LIỆU FILE THỰC TẾ & ĐO THỜI GIAN + KIỂM TRA SHA-256")
    print("=" * 75)
    # Tạo một file dữ liệu mẫu 10 KB để kiểm thử trực tiếp
    sample_data = os.urandom(10 * 1024) # 10 KB dữ liệu nhị phân ngẫu nhiên (như file ảnh/văn bản)
    original_hash = hashlib.sha256(sample_data).hexdigest()
    
    start_time = time.time()
    file_blocks = bytes_to_bit_blocks(sample_data, mhk_full.n)
    enc_file = [mhk_full.encrypt_block(b) for b in file_blocks]
    enc_time = time.time() - start_time

    start_dec = time.time()
    dec_file_blocks = [mhk_full.decrypt_block(c) for c in enc_file]
    recovered_file_data = bit_blocks_to_bytes(dec_file_blocks)
    dec_time = time.time() - start_dec

    recovered_hash = hashlib.sha256(recovered_file_data).hexdigest()
    print(f"[*] Kích thước dữ liệu mẫu : 10 KB ({len(sample_data)} bytes)")
    print(f"[*] Thời gian mã hóa       : {enc_time:.4f} giây")
    print(f"[*] Thời gian giải mã      : {dec_time:.4f} giây")
    print(f"[*] SHA-256 gốc            : {original_hash}")
    print(f"[*] SHA-256 sau giải mã    : {recovered_hash}")
    assert original_hash == recovered_hash
    print("[✓] KẾT QUẢ: Mã băm SHA-256 trùng khớp tuyệt đối! File khôi phục nguyên vẹn.")

if __name__ == "__main__":
    run_all_demos()