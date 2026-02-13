import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime
import hashlib
import time

st.set_page_config(page_title="Voting Portal", layout="wide")

# ======================================================
# DATABASE CONNECTION (CLOUD SAFE VERSION)
# ======================================================

@st.cache_resource
def get_connection():
    conn = sqlite3.connect(
        "voting_system.db",
        check_same_thread=False
    )
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

conn = get_connection()

# ======================================================
# SAFE EXECUTE (LOCK SAFE)
# ======================================================

def safe_execute(query, params=()):
    for _ in range(3):
        try:
            conn.execute(query, params)
            conn.commit()
            return
        except sqlite3.OperationalError:
            time.sleep(0.3)

# ======================================================
# TABLE CREATION
# ======================================================

conn.execute("""
CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    password TEXT,
    role TEXT DEFAULT 'user',
    vote_limit INTEGER DEFAULT 1,
    vote_weight INTEGER DEFAULT 1
)
""")

conn.execute("""
CREATE TABLE IF NOT EXISTS nominations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,
    description TEXT,
    added_by TEXT,
    added_time TEXT
)
""")

conn.execute("""
CREATE TABLE IF NOT EXISTS votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    candidate TEXT,
    score INTEGER,
    vote_time TEXT,
    FOREIGN KEY(email) REFERENCES users(email) ON DELETE CASCADE
)
""")

conn.commit()

# ======================================================
# SAFE MIGRATION (AUTO FIX FOR CLOUD)
# ======================================================

columns = [col[1] for col in conn.execute("PRAGMA table_info(users)").fetchall()]

if "vote_limit" not in columns:
    conn.execute("ALTER TABLE users ADD COLUMN vote_limit INTEGER DEFAULT 1")

if "vote_weight" not in columns:
    conn.execute("ALTER TABLE users ADD COLUMN vote_weight INTEGER DEFAULT 1")

conn.commit()

safe_execute("UPDATE users SET vote_limit=1 WHERE vote_limit IS NULL")
safe_execute("UPDATE users SET vote_weight=1 WHERE vote_weight IS NULL")

# ======================================================
# HASH FUNCTION
# ======================================================

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ======================================================
# DEFAULT ADMIN (Super Admin)
# ======================================================

if not conn.execute("SELECT * FROM users WHERE email='admin@admin.com'").fetchone():
    safe_execute(
        "INSERT INTO users VALUES (?,?,?,?,?)",
        ("admin@admin.com", hash_password("admin123"), "admin", 5, 2)
    )

# ======================================================
# DEFAULT USERS
# ======================================================

default_users = [
    ("user1@test.com","1234"),
    ("user2@test.com","1234"),
    ("user3@test.com","1234"),
]

for email, pwd in default_users:
    if not conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone():
        safe_execute(
            "INSERT INTO users VALUES (?,?,?,?,?)",
            (email, hash_password(pwd), "user", 1, 1)
        )

# ======================================================
# DEFAULT NOMINATIONS
# ======================================================

default_noms = [
    ("user1@test.com","Consistent performance and dedication."),
    ("user2@test.com","Strong teamwork and collaboration.")
]

for name, desc in default_noms:
    if not conn.execute("SELECT * FROM nominations WHERE name=?", (name,)).fetchone():
        safe_execute(
            "INSERT INTO nominations (name,description,added_by,added_time) VALUES (?,?,?,?)",
            (name, desc, "system", datetime.now())
        )

# ======================================================
# SESSION
# ======================================================

if "user" not in st.session_state:
    st.session_state.user = None
if "role" not in st.session_state:
    st.session_state.role = None

# ======================================================
# 🏆 LIVE SCORE BOARD (SAFE QUERY)
# ======================================================

st.markdown("## 🏆 Live Score Board")

try:
    df_live = pd.read_sql("""
    SELECT v.candidate,
           SUM(v.score * COALESCE(u.vote_weight,1)) as total
    FROM votes v
    JOIN users u ON v.email = u.email
    GROUP BY v.candidate
    ORDER BY total DESC
    """, conn)

    if not df_live.empty:
        st.dataframe(df_live, use_container_width=True)
    else:
        st.info("No votes yet.")

except:
    st.info("Leaderboard not available yet.")

st.markdown("---")

# ======================================================
# LOGIN / REGISTER
# ======================================================

if st.session_state.user is None:

    st.title("🏆 Nomination Voting Portal")

    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    col1, col2 = st.columns(2)

    with col1:
        if st.button("Register"):
            try:
                safe_execute(
                    "INSERT INTO users VALUES (?,?,?,?,?)",
                    (email, hash_password(password), "user", 1, 1)
                )
                st.success("Registered")
            except:
                st.error("User exists")

    with col2:
        if st.button("Login"):
            user = conn.execute(
                "SELECT email,role FROM users WHERE email=? AND password=?",
                (email, hash_password(password))
            ).fetchone()

            if user:
                st.session_state.user = user[0]
                st.session_state.role = user[1]
                st.rerun()
            else:
                st.error("Invalid credentials")

# ======================================================
# AFTER LOGIN
# ======================================================

else:

    st.success(f"Logged in as: {st.session_state.user}")
    st.sidebar.button("Logout", on_click=lambda: st.session_state.clear())

    # Reset password
    st.sidebar.markdown("### 🔐 Reset My Password")
    new_pass = st.sidebar.text_input("New Password", type="password")
    if st.sidebar.button("Reset Password"):
        safe_execute(
            "UPDATE users SET password=? WHERE email=?",
            (hash_password(new_pass), st.session_state.user)
        )
        st.sidebar.success("Updated")

    # ==================================================
    # ADMIN PANEL
    # ==================================================

    if st.session_state.role == "admin":

        admin_option = st.sidebar.radio(
            "Admin Controls",
            ["Dashboard","Manage Users","Manage Nominations","View Votes","Analytics"]
        )

        if admin_option == "Dashboard":
            total_users = pd.read_sql("SELECT COUNT(*) count FROM users", conn)["count"][0]
            total_votes = pd.read_sql("SELECT COUNT(*) count FROM votes", conn)["count"][0]
            st.metric("Total Users", total_users)
            st.metric("Total Votes", total_votes)

        if admin_option == "Manage Users":

            df_users = pd.read_sql("SELECT * FROM users", conn)
            st.dataframe(df_users)

            st.subheader("➕ Create User")
            email = st.text_input("Email")
            pwd = st.text_input("Password")
            role = st.selectbox("Role",["user","admin","superuser"])

            if st.button("Create User"):
                vote_limit = 5 if role=="superuser" else 1
                vote_weight = 2 if role=="superuser" else 1
                safe_execute(
                    "INSERT INTO users VALUES (?,?,?,?,?)",
                    (email, hash_password(pwd), role, vote_limit, vote_weight)
                )
                st.success("User Created")
                st.rerun()

            st.subheader("❌ Delete User")
            del_user = st.selectbox("Delete User", df_users["email"])
            if st.button("Delete User"):
                safe_execute("DELETE FROM users WHERE email=?", (del_user,))
                st.success("User & Votes Deleted Automatically")
                st.rerun()

        if admin_option == "Manage Nominations":

            df_nom = pd.read_sql("SELECT * FROM nominations", conn)
            st.dataframe(df_nom)

            edit = st.selectbox("Edit Nominee", df_nom["name"])
            new_desc = st.text_area("New Description")
            if st.button("Update"):
                safe_execute(
                    "UPDATE nominations SET description=? WHERE name=?",
                    (new_desc, edit)
                )
                st.success("Updated")
                st.rerun()

            delete = st.selectbox("Delete Nominee", df_nom["name"])
            if st.button("Delete Nominee"):
                safe_execute("DELETE FROM nominations WHERE name=?", (delete,))
                st.success("Deleted")
                st.rerun()

        if admin_option == "View Votes":
            df_votes = pd.read_sql("SELECT * FROM votes", conn)
            st.dataframe(df_votes)

        if admin_option == "Analytics":
            df = pd.read_sql("""
            SELECT v.candidate,
                   AVG(v.score) as avg,
                   COUNT(v.id) as votes,
                   SUM(v.score * COALESCE(u.vote_weight,1)) as total
            FROM votes v
            JOIN users u ON v.email = u.email
            GROUP BY v.candidate
            ORDER BY total DESC
            """, conn)

            if not df.empty:
                st.bar_chart(df.set_index("candidate")["total"])

    # ==================================================
    # VOTING SECTION
    # ==================================================

    user_data = conn.execute(
        "SELECT vote_limit FROM users WHERE email=?",
        (st.session_state.user,)
    ).fetchone()

    vote_limit = user_data[0]

    used_votes = conn.execute(
        "SELECT COUNT(*) FROM votes WHERE email=?",
        (st.session_state.user,)
    ).fetchone()[0]

    remaining = vote_limit - used_votes

    st.info(f"Remaining Votes: {remaining}")

    if remaining > 0:
        df_nom = pd.read_sql("SELECT name,description FROM nominations", conn)
        selected = st.radio("Select Nominee", df_nom["name"])
        st.info(df_nom[df_nom["name"]==selected]["description"].values[0])
        score = st.slider("Score",1,10)

        if st.button("Submit Vote"):
            safe_execute(
                "INSERT INTO votes (email,candidate,score,vote_time) VALUES (?,?,?,?)",
                (st.session_state.user, selected, score, datetime.now())
            )
            st.success("Vote Submitted")
            st.rerun()
    else:
        st.warning("Vote limit reached.")

    # Self Nomination
    st.markdown("---")
    desc = st.text_area("Nominate Yourself - Description")
    if st.button("Submit Self Nomination"):
        if not conn.execute("SELECT * FROM nominations WHERE name=?",
                            (st.session_state.user,)).fetchone():
            safe_execute(
                "INSERT INTO nominations (name,description,added_by,added_time) VALUES (?,?,?,?)",
                (st.session_state.user, desc, st.session_state.user, datetime.now())
            )
            st.success("Added")
            st.rerun()

# ======================================================
# 🏅 MEDAL LEADERBOARD
# ======================================================

st.markdown("---")
st.subheader("🏅 Medal Leaderboard")

try:
    df = pd.read_sql("""
    SELECT v.candidate,
           AVG(v.score) as avg,
           COUNT(v.id) as votes,
           SUM(v.score * COALESCE(u.vote_weight,1)) as total
    FROM votes v
    JOIN users u ON v.email = u.email
    GROUP BY v.candidate
    ORDER BY total DESC
    """, conn)

    if not df.empty:

        medals = ["🥇","🥈","🥉"]
        df["Medal"] = ""

        for i in range(min(3,len(df))):
            df.loc[i,"Medal"] = medals[i]

        for _, row in df.iterrows():
            st.markdown(f"""
            <div style='padding:15px;margin:10px 0;border-radius:12px;background:#f2f6fc'>
                <h3>{row['Medal']} {row['candidate']}</h3>
                ⭐ Avg: {round(row['avg'],2)} |
                🗳 Votes: {row['votes']} |
                🔢 Weighted Total: {row['total']}
            </div>
            """, unsafe_allow_html=True)

        st.bar_chart(df.set_index("candidate")["total"])
    else:
        st.info("No votes yet.")

except:
    st.info("Leaderboard not available yet.")
