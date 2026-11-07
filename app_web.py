import streamlit as st
import time
import hashlib
from mhk_complete import (
    MerkleHellmanKnapsack,
    bytes_to_bit_blocks,
    bit_blocks_to_bytes,
    gcd,
    is_superincreasing
)

st.set_page_config(page_title="Demo Hệ Mã Ba Lô MHK", layout="wide")
st.title("🔐 Hệ Mã Khóa Công Khai Ba Lô Merkle–Hellman (MHK)")

tab1, tab2, tab3 = st.tabs([
    "1. Phiên bản thu nhỏ (Đối chiếu tính tay)",
    "2. Mã hóa Văn bản & File thực tế (64-bit)",
    "3. Minh họa Tấn công Phá mã (Attack Demo)"
])

# --- TAB 1: PHIÊN BẢN THU NHỎ ---
with tab1:
    st.subheader("Mô phỏng từng bước (Khớp với ví dụ tính tay trong báo cáo)")
    col1, col2 = st.columns(2)
    with col1:
        w_str = st.text_input("Dãy siêu tăng W (cách nhau bởi dấu phẩy):", "2, 3, 7, 14, 30, 57, 120, 250")
        q_val = st.number_input("Số modulo q (q > sum(W)):", value=491, step=1)
        r_val = st.number_input("Số nhân r (gcd(r, q) = 1):", value=41, step=1)
        char_input = st.text_input("Nhập 1 ký tự ASCII cần mã hóa:", "A", max_chars=1)

    if st.button("Chạy mô phỏng từng bước", type="primary"):
        try:
            W = [int(x.strip()) for x in w_str.split(",")]
            mhk = MerkleHellmanKnapsack(W=W, q=int(q_val), r=int(r_val))
            
            ascii_val = ord(char_input)
            bits = [(ascii_val >> i) & 1 for i in range(mhk.n - 1, -1, -1)]
            
            with col2:
                st.success(f"**Khóa công khai B:** `{mhk.B}`")
                st.info(f"**Khóa riêng:** `W = {mhk.W}`, `q = {mhk.q}`, `r = {mhk.r}` (Nghịch đảo `r^-1 = {mhk.r_inv}`)")
                C = mhk.encrypt_block(bits)
                st.warning(f"**Bản rõ:** `'{char_input}'` (ASCII: `{ascii_val}`) $\\rightarrow$ Chuỗi bit: `{bits}`\n\n**Bản mã thu được:** `C = {C}`")

            # Bảng giải mã từng bước
            S_prime = (C * mhk.r_inv) % mhk.q
            st.markdown(f"**Bước quy đổi về tổng siêu tăng:** $S' = (C \\times r^{{-1}}) \\bmod q = ({C} \\times {mhk.r_inv}) \\bmod {mhk.q} = \\mathbf{{{S_prime}}}$")
            
            rows = []
            rem = S_prime
            dec_bits = [0] * mhk.n
            for i in range(mhk.n - 1, -1, -1):
                w_i = mhk.W[i]
                old_rem = rem
                if rem >= w_i:
                    bit = 1
                    rem -= w_i
                    cmp_text = f"{old_rem} >= {w_i} (Chọn)"
                else:
                    bit = 0
                    cmp_text = f"{old_rem} < {w_i} (Bỏ qua)"
                dec_bits[i] = bit
                rows.append({
                    "Bước (i)": f"i = {i+1}",
                    "Trọng số w_i": w_i,
                    "Tổng S' trước khi trừ": old_rem,
                    "So sánh S' >= w_i": cmp_text,
                    "Bit x_i": bit,
                    "Tổng S' còn lại": rem
                })
            st.table(rows)
            st.success(f"**Chuỗi bit khôi phục (từ x_1 đến x_{mhk.n}):** `{dec_bits}` $\\rightarrow$ Ký tự: `'{chr(int(''.join(map(str, dec_bits)), 2))}'`")
        except Exception as e:
            st.error(f"Lỗi thông số: {e}")

# --- TAB 2: MÃ HÓA FILE & VĂN BẢN ---
with tab2:
    st.subheader("Mã hóa dữ liệu thực tế với khóa 64-bit ngẫu nhiên")
    if "mhk_full" not in st.session_state:
        st.session_state.mhk_full = MerkleHellmanKnapsack(bit_length=64)
    
    if st.button("🔄 Sinh bộ khóa 64-bit mới"):
        st.session_state.mhk_full = MerkleHellmanKnapsack(bit_length=64)
        st.toast("Đã sinh cặp khóa 64-bit mới!")

    mhk_full = st.session_state.mhk_full
    st.caption(f"Modulo $q$ hiện tại ({mhk_full.q.bit_length()} bits): `{mhk_full.q}` | Số nhân $r$: `{mhk_full.r}`")

    uploaded_file = st.file_uploader("Tải lên tệp văn bản (.txt) hoặc ảnh nhỏ (.png, .jpg) để kiểm thử:", type=["txt", "png", "jpg", "jpeg"])
    if uploaded_file is not None:
        raw_bytes = uploaded_file.read()
        orig_hash = hashlib.sha256(raw_bytes).hexdigest()
        st.write(f"**Kích thước tệp gốc:** `{len(raw_bytes)} bytes` | **SHA-256 gốc:** `{orig_hash}`")

        if st.button("Thực hiện Mã hóa & Giải mã File"):
            t0 = time.time()
            blocks = bytes_to_bit_blocks(raw_bytes, mhk_full.n)
            cipher_blocks = [mhk_full.encrypt_block(b) for b in blocks]
            enc_time = time.time() - t0

            t1 = time.time()
            dec_blocks = [mhk_full.decrypt_block(c) for c in cipher_blocks]
            recovered_bytes = bit_blocks_to_bytes(dec_blocks)
            dec_time = time.time() - t1
            rec_hash = hashlib.sha256(recovered_bytes).hexdigest()

            c1, c2, c3 = st.columns(3)
            c1.metric("Số khối 64-bit", f"{len(blocks)} khối")
            c2.metric("Thời gian mã hóa", f"{enc_time*1000:.2f} ms")
            c3.metric("Thời gian giải mã", f"{dec_time*1000:.2f} ms")

            st.write(f"**SHA-256 sau giải mã:** `{rec_hash}`")
            if orig_hash == rec_hash:
                st.success("✓ Toàn vẹn dữ liệu 100%! Bản rõ khôi phục trùng khớp tuyệt đối với tệp ban đầu.")
                st.download_button("⬇️ Tải tệp đã khôi phục về máy", data=recovered_bytes, file_name=f"decrypted_{uploaded_file.name}")

# --- TAB 3: MINH HỌA TẤN CÔNG PHÁ MÃ ---
with tab3:
    st.subheader("Tấn công phá mã MHK không cần khóa riêng (Meet-in-the-Middle / Shamir Search)")
    st.markdown("Kẻ tấn công chỉ biết **Khóa công khai $B$** và **Bản mã $C$**, hoàn toàn không biết $W, q, r$.")
    if st.button("Chạy kịch bản tấn công trên khóa 8-bit"):
        B_pub = [82, 123, 287, 83, 248, 373, 10, 430]
        C_target = 553
        st.write(f"**Dữ liệu kẻ tấn công thu thập được:** `B = {B_pub}`, `C = {C_target}`")
        
        t_start = time.time()
        # Chia đôi tập B (Meet-in-the-Middle) để tìm tổ hợp tổng bằng C trong thời gian O(2^(n/2))
        half = len(B_pub) // 2
        left_sums = {}
        for mask in range(1 << half):
            s = sum(B_pub[i] for i in range(half) if (mask >> i) & 1)
            left_sums[s] = [(mask >> i) & 1 for i in range(half)]
            
        cracked_bits = None
        for mask in range(1 << (len(B_pub) - half)):
            s_right = sum(B_pub[half + i] for i in range(len(B_pub) - half) if (mask >> i) & 1)
            if (C_target - s_right) in left_sums:
                right_bits = [(mask >> i) & 1 for i in range(len(B_pub) - half)]
                cracked_bits = left_sums[C_target - s_right] + right_bits
                break
        t_attack = (time.time() - t_start) * 1000
        
        if cracked_bits:
            cracked_char = chr(int("".join(map(str, cracked_bits)), 2))
            st.error(f"💥 **PHÁ MÃ THÀNH CÔNG TRONG {t_attack:.3f} ms!**\n\nTìm ra chuỗi bit: `{cracked_bits}` $\\rightarrow$ Ký tự gốc: `'{cracked_char}'` mà không cần khóa riêng.")