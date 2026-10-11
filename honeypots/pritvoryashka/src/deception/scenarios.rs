pub const AUTH_LOG: &str = "Oct 11 03:14:19 srv-app-01 sshd[1842]: Accepted publickey for deploy from 10.20.4.18 port 49122 ssh2\nOct 11 03:15:02 srv-app-01 sudo: deploy : TTY=pts/1 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/systemctl restart billing\n";
pub const BACKUP_ENV: &str = "APP_ENV=production\nDB_HOST=db-internal\nDB_USER=billing_ro\nDB_PASSWORD=decoy-only-not-a-real-secret\n";
pub const SSH_CONFIG: &str = "Host db-internal\n    HostName 10.20.4.12\n    User deploy\n    IdentityFile ~/.ssh/id_deploy_decoy\n";
