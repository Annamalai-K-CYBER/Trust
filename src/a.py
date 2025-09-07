import psycopg2

conn = psycopg2.connect(
    "postgresql://neondb_owner:npg_dIk5BXwjLP4a@ep-solitary-cell-a17e517q-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require"
)
cur = conn.cursor()

cur.execute("SELECT * FROM users;")
rows = cur.fetchall()

for row in rows:
    print(row)

cur.close()
conn.close()
