export PGPASSWORD=app1pw
while true; do
  psql -h world-proxy -p 6432 -U app1 -d postgres -q -f /world/work.sql > /dev/null 2>&1
done
