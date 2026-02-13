import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime
import hashlib
import time

# =============================
# CONFIG
# =============================
st.set_page_config(page_title="Voting Portal", layout="wide")

# =============================
# DATABASE
# =============================
conn = sqlite3.connect("voting_system.db", check_same_thread=False)
c = conn.cursor()

# =============================
# TABLE CREATION
# =============================
c.execute("""
CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    password TEXT,
    role TEXT DEFAULT 'user'
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS nominations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,
    description TEXT,
    added_by TEXT,
    added_time TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    candidate TEXT,
    score INTEGER,
    vote_time TEXT
)
""")

conn.commit()

# =============================
# PASSWORD HASH FUNCTION
# =============================
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# =============================
# DEFAULT ADMIN
# =============================
ADMIN_EMAIL = "admin@admin.com"
ADMIN_PASS = hash_password("admin123")

if not c.execute("SELECT * FROM users WHERE email=?", (ADMIN_EMAIL,)).fetchone():
    c.execute(
        "INSERT INTO users (email,password,role) VALUES (?,?,?)",
        (ADMIN_EMAIL, ADMIN_PASS, "admin")
    )
    conn.commit()
# =============================
# DEFAULT NOMINATIONS
# =============================
default_candidates = [
    ("User1","Outstanding leadership and team management."),
    ("User2","Consistently exceeded performance targets."),

]

if c.execute("SELECT COUNT(*) FROM nominations").fetchone()[0] == 0:
    for name, desc in default_candidates:
        c.execute(
            "INSERT INTO nominations (name,description,added_by,added_time) VALUES (?,?,?,?)",
            (name, desc, "system", datetime.now())
        )
    conn.commit()
# =============================
# DEFAULT USERS (NEW)
# =============================
default_users = [
    ("user1@test.com","1234"),
    ("user2@test.com","1234"),
]

for email, pwd in default_users:
    if not c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone():
        c.execute(
            "INSERT INTO users (email,password,role) VALUES (?,?,?)",
            (email, hash_password(pwd), "user")
        )
conn.commit()

# =============================
# SESSION STATE
# =============================
if "user" not in st.session_state:
    st.session_state.user = None
if "role" not in st.session_state:
    st.session_state.role = None

# =============================
# LOGIN / REGISTER
# =============================
if st.session_state.user is None:

    st.title("🏆 Nomination Voting Portal")
    st.subheader("🔐 Login or Register")

    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    col1, col2 = st.columns(2)

    with col1:
        if st.button("Register"):
            if email and password:
                try:
                    c.execute(
                        "INSERT INTO users (email,password) VALUES (?,?)",
                        (email, hash_password(password))
                    )
                    conn.commit()
                    st.success("Registered successfully!")
                except:
                    st.error("User already exists")

    with col2:
        if st.button("Login"):
            user = c.execute(
                "SELECT email,role FROM users WHERE email=? AND password=?",
                (email, hash_password(password))
            ).fetchone()

            if user:
                st.session_state.user = user[0]
                st.session_state.role = user[1]
                st.rerun()
            else:
                st.error("Invalid credentials")

# =============================
# AFTER LOGIN
# =============================
else:

    st.success(f"Logged in as: {st.session_state.user}")
    st.sidebar.button("Logout", on_click=lambda: st.session_state.clear())

    # =============================
    # ADMIN PANEL
    # =============================
    if st.session_state.role == "admin":

        st.sidebar.header("⚙ Admin Panel")
        admin_option = st.sidebar.radio(
            "Admin Controls",
            ["Dashboard","Manage Nominations","View Votes","Manage Users"]
        )

        if admin_option == "Dashboard":
            total_users = pd.read_sql("SELECT COUNT(*) count FROM users", conn)["count"][0]
            total_votes = pd.read_sql("SELECT COUNT(*) count FROM votes", conn)["count"][0]
            st.metric("Total Users", total_users)
            st.metric("Total Votes", total_votes)

        if admin_option == "Manage Users":
            df_users = pd.read_sql("SELECT email,password,role FROM users", conn)
            st.dataframe(df_users)

        if admin_option == "Manage Nominations":
            df_nom = pd.read_sql("SELECT * FROM nominations", conn)
            st.dataframe(df_nom)

        if admin_option == "View Votes":
            df_votes = pd.read_sql("SELECT * FROM votes", conn)
            st.dataframe(df_votes)

    # =============================
    # NORMAL USER PANEL
    # =============================
    else:

        voted = c.execute(
            "SELECT * FROM votes WHERE email=?",
            (st.session_state.user,)
        ).fetchone()

        if voted:
            st.warning("⚠ You have already voted.")
        else:

            st.subheader("🗳 Cast Your Vote")

            df_nom = pd.read_sql("SELECT name,description FROM nominations", conn)

            if not df_nom.empty:
                selected = st.radio("Select Nominee", df_nom["name"])
                desc = df_nom[df_nom["name"] == selected]["description"].values[0]
                st.info(desc)

                score = st.slider("Score (1-10)",1,10)

                if st.button("Submit Vote"):
                    c.execute(
                        "INSERT INTO votes (email,candidate,score,vote_time) VALUES (?,?,?,?)",
                        (st.session_state.user, selected, score, datetime.now())
                    )
                    conn.commit()
                    st.success("Vote submitted!")
                    time.sleep(1)
                    st.rerun()

        # =============================
        # SELF NOMINATION (NEW)
        # =============================
        st.markdown("---")
        st.subheader("🙋 Nominate Yourself")

        self_desc = st.text_area("Describe why you deserve nomination")

        if st.button("Submit Self Nomination"):

            already = c.execute(
                "SELECT * FROM nominations WHERE name=?",
                (st.session_state.user,)
            ).fetchone()

            if already:
                st.warning("You already nominated yourself.")
            else:
                c.execute(
                    "INSERT INTO nominations (name,description,added_by,added_time) VALUES (?,?,?,?)",
                    (st.session_state.user, self_desc, st.session_state.user, datetime.now())
                )
                conn.commit()
                st.success("Self nomination submitted!")
                st.rerun()

    # =============================
    # LEADERBOARD
    # =============================
    st.markdown("---")
    st.subheader("🏆 Live Leaderboard")

    df = pd.read_sql("SELECT * FROM votes", conn)

    if not df.empty:

        leaderboard = (
            df.groupby("candidate")["score"]
            .agg(["mean","count","sum"])
            .reset_index()
            .sort_values("mean", ascending=False)
        )

        leaderboard.columns = ["Candidate","Average Score","Votes","Total Score"]

        for _, row in leaderboard.iterrows():
            st.markdown(f"""
            <div style='padding:12px;margin:8px 0;border-radius:8px;background:#f0f2f6'>
                <h4>{row['Candidate']}</h4>
                ⭐ Avg: {round(row['Average Score'],2)}
                🗳 Votes: {row['Votes']}
                🔢 Total Score: {row['Total Score']}
            </div>
            """, unsafe_allow_html=True)

        st.bar_chart(leaderboard.set_index("Candidate")["Average Score"])

    else:
        st.info("No votes yet.")
