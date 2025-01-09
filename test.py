
import psycopg2

hostname='localhost'
database='test_db'
username='postgres'
pwd=1234
port_id=5432

try:

    conn=psycopg2.connect(host=hostname,
                        dbname=database,
                        user=username,
                        password=pwd,
                        port=port_id)
    
    cur=conn.cursor()

    # create_script='CREATE TABLE employee(id int primary key,name varchar(30),salary int,dept_id varchar(30))'
    # cur.execute(create_script)

    insert_cmd='INSERT INTO employee(id,name,salary,dept_id) VALUES (%s,%s,%s ,%s)'
    insert_val=[(1,'Joyce',35000,'D1'),(2,'Shelvin',40000,'D2')]
    for record in insert_val:
        cur.execute(insert_cmd,record)

    conn.commit()


    cur.close()
    conn.close()

except Exception as e:
    print(e)



