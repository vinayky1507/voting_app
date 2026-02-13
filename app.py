import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime
import hashlib
import time

st.set_page_config(page_title="Voting Portal", layout="wide")

# =============================
# DATABASE
# =============================
conn = sqlite3.connect("voting_system.db", check_same_thread=False)
c = conn.cursor()

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
# HASH FUNCTION
# =============================
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# =============================
# DEFAULT ADMIN
# =============================
if not c.execute("SELECT * FROM users WHERE email='admin@admin.com'").fetchone():
    c.execute(
        "INSERT INTO users VALUES (?,?,?)",
        ("admin@admin.com", hash_password("admin123"), "admin")
    )
    conn.commit()

# =============================
# DEFAULT USERS
# =============================
default_users = [
    ("user1@test.com","1234"),
    ("user2@test.com","1234"),
    ("user3@test.com","1234"),
]

for email, pwd in default_users:
    if not c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone():
        c.execute(
            "INSERT INTO users VALUES (?,?,?)",
            (email, hash_password(pwd), "user")
        )
conn.commit()

# =============================
# DEFAULT NOMINATIONS
# =============================
default_noms = [
    ("user1@test.com","Consistent performance and dedication."),
    ("user2@test.com","Strong teamwork and collaboration.")
]

for name, desc in default_noms:
    if not c.execute("SELECT * FROM nominations WHERE name=?", (name,)).fetchone():
        c.execute(
            "INSERT INTO nominations (name,description,added_by,added_time) VALUES (?,?,?,?)",
            (name, desc, "system", datetime.now())
        )
conn.commit()

# =============================
# SESSION
# =============================
if "user" not in st.session_state:
    st.session_state.user = None
if "role" not in st.session_state:
    st.session_state.role = None

# =============================
# LOGIN
# =============================
if st.session_state.user is None:

    st.title("🏆 Nomination Voting Portal")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    col1, col2 = st.columns(2)

    with col1:
        if st.button("Register"):
            try:
                c.execute("INSERT INTO users VALUES (?,?,?)",
                          (email, hash_password(password), "user"))
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

    # 🔐 USER RESET PASSWORD
    st.sidebar.markdown("### 🔐 Reset My Password")
    new_pass = st.sidebar.text_input("New Password", type="password")
    if st.sidebar.button("Reset Password"):
        c.execute("UPDATE users SET password=? WHERE email=?",
                  (hash_password(new_pass), st.session_state.user))
        conn.commit()
        st.sidebar.success("Password Updated")

    # =============================
    # ADMIN PANEL
    # =============================
    if st.session_state.role == "admin":

        admin_option = st.sidebar.radio(
            "Admin Controls",
            ["Dashboard","Manage Users","Manage Nominations","View Votes","Analytics"]
        )

        # DASHBOARD
        if admin_option == "Dashboard":
            total_users = pd.read_sql("SELECT COUNT(*) count FROM users", conn)["count"][0]
            total_votes = pd.read_sql("SELECT COUNT(*) count FROM votes", conn)["count"][0]
            st.metric("Total Users", total_users)
            st.metric("Total Votes", total_votes)

        # MANAGE USERS
        if admin_option == "Manage Users":
            df_users = pd.read_sql("SELECT * FROM users", conn)
            st.dataframe(df_users)

            st.subheader("➕ Create User")
            email = st.text_input("Email")
            pwd = st.text_input("Password")
            role = st.selectbox("Role",["user","admin"])
            if st.button("Create User"):
                try:
                    c.execute("INSERT INTO users VALUES (?,?,?)",
                              (email, hash_password(pwd), role))
                    conn.commit()
                    st.success("User Created")
                    st.rerun()
                except:
                    st.error("User exists")

            st.subheader("🔐 Reset Any User Password")
            sel_user = st.selectbox("Select User", df_users["email"])
            reset_pwd = st.text_input("New Password for User")
            if st.button("Admin Reset Password"):
                c.execute("UPDATE users SET password=? WHERE email=?",
                          (hash_password(reset_pwd), sel_user))
                conn.commit()
                st.success("Password Reset")

            st.subheader("❌ Delete User")
            del_user = st.selectbox("Delete User", df_users["email"])
            if st.button("Delete User"):
                c.execute("DELETE FROM users WHERE email=?", (del_user,))
                conn.commit()
                st.success("Deleted")
                st.rerun()

        # MANAGE NOMINATIONS
        if admin_option == "Manage Nominations":
            df_nom = pd.read_sql("SELECT * FROM nominations", conn)
            st.dataframe(df_nom)

            edit = st.selectbox("Edit Nominee", df_nom["name"])
            new_desc = st.text_area("New Description")
            if st.button("Update"):
                c.execute("UPDATE nominations SET description=? WHERE name=?",
                          (new_desc, edit))
                conn.commit()
                st.success("Updated")
                st.rerun()

            delete = st.selectbox("Delete Nominee", df_nom["name"])
            if st.button("Delete"):
                c.execute("DELETE FROM nominations WHERE name=?", (delete,))
                conn.commit()
                st.success("Deleted")
                st.rerun()

        # VIEW VOTES
        if admin_option == "View Votes":
            df_votes = pd.read_sql("SELECT * FROM votes", conn)
            st.dataframe(df_votes)

        # 📊 ANALYTICS
        if admin_option == "Analytics":
            df = pd.read_sql("SELECT * FROM votes", conn)

            if not df.empty:
                agg = df.groupby("candidate")["score"].agg(["mean","count","sum"]).reset_index()
                agg.columns = ["Candidate","Average","Votes","Total"]

                st.subheader("Average Score Chart")
                st.bar_chart(agg.set_index("Candidate")["Average"])

                st.subheader("Total Score Chart")
                st.bar_chart(agg.set_index("Candidate")["Total"])

                top = agg.sort_values("Average", ascending=False).iloc[0]
                st.success(f"🏆 Top Performer: {top['Candidate']} (Avg: {round(top['Average'],2)})")

    # =============================
    # NORMAL USER
    # =============================
    else:

        voted = c.execute("SELECT * FROM votes WHERE email=?",
                          (st.session_state.user,)).fetchone()

        if voted:
            st.warning("You already voted.")
        else:
            df_nom = pd.read_sql("SELECT name,description FROM nominations", conn)
            selected = st.radio("Select Nominee", df_nom["name"])
            st.info(df_nom[df_nom["name"]==selected]["description"].values[0])
            score = st.slider("Score",1,10)

            if st.button("Submit Vote"):
                c.execute("INSERT INTO votes (email,candidate,score,vote_time) VALUES (?,?,?,?)",
                          (st.session_state.user, selected, score, datetime.now()))
                conn.commit()
                st.success("Vote Submitted")
                st.rerun()

        # Self Nomination
        st.markdown("---")
        desc = st.text_area("Nominate Yourself - Description")
        if st.button("Submit Self Nomination"):
            if not c.execute("SELECT * FROM nominations WHERE name=?",
                             (st.session_state.user,)).fetchone():
                c.execute("INSERT INTO nominations (name,description,added_by,added_time) VALUES (?,?,?,?)",
                          (st.session_state.user, desc, st.session_state.user, datetime.now()))
                conn.commit()
                st.success("Added")
                st.rerun()

    # =============================
    # 🏅 MEDAL LEADERBOARD
    # =============================
    st.markdown("---")
    st.subheader("🏅 Live Medal Leaderboard")

    df = pd.read_sql("SELECT * FROM votes", conn)

    if not df.empty:
        lb = df.groupby("candidate")["score"].agg(["mean","count","sum"]).reset_index()
        lb.columns = ["Candidate","Average","Votes","Total"]
        lb = lb.sort_values("Average", ascending=False).reset_index(drop=True)

        medals = ["🥇","🥈","🥉"]
        lb["Medal"] = ""

        for i in range(min(3,len(lb))):
            lb.loc[i,"Medal"] = medals[i]

        for _, row in lb.iterrows():
            st.markdown(f"""
            <div style='padding:15px;margin:10px 0;border-radius:12px;background:#f2f6fc'>
                <h3>{row['Medal']} {row['Candidate']}</h3>
                ⭐ Avg: {round(row['Average'],2)} |
                🗳 Votes: {row['Votes']} |
                🔢 Total: {row['Total']}
            </div>
            """, unsafe_allow_html=True)

        st.bar_chart(lb.set_index("Candidate")["Average"])
    else:
        st.info("No votes yet.")
