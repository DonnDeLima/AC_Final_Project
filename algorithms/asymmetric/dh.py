import streamlit as st

def generate_keys(name, private_key):
    fixed_offset = 7
    public_key = private_key + fixed_offset if name == "Alice" else private_key - fixed_offset
    return public_key

def compute_shared_key(my_private, their_public, name):
    fixed_offset = 7
    return their_public - fixed_offset if name == "Alice" else their_public + fixed_offset

def run():
    st.subheader("🔐 Simplified Key-Pair Cryptography Demo")

    col1, col2 = st.columns(2)
    with col1:
        alice_private = st.number_input("🔑 Alice's Private Key", value=11)
    with col2:
        bob_private = st.number_input("🔑 Bob's Private Key", value=23)

    alice_public = generate_keys("Alice", alice_private)
    bob_public = generate_keys("Bob", bob_private)

    st.markdown("---")
    st.markdown("### 🧾 Public Keys")
    col1, col2 = st.columns(2)
    with col1:
        st.info(f"Alice's Public Key: `{alice_public}`")
    with col2:
        st.info(f"Bob's Public Key: `{bob_public}`")

    alice_shared = compute_shared_key(alice_private, bob_public, "Alice")
    bob_shared = compute_shared_key(bob_private, alice_public, "Bob")

    st.markdown("---")
    st.markdown("### 🔐 Shared Secret")
    if alice_shared == bob_shared:
        st.success(f"Shared Key: `{alice_shared}` ✅")
    else:
        st.error(f"Mismatch! Alice: `{alice_shared}` | Bob: `{bob_shared}` ❌")

if __name__ == "__main__":
    run()
