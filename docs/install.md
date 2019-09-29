# Installation
In order for installation to complete successfully, you will need the following dependencies installed.
* zlib1g-dev 
* libbz2-dev
* cmake

Additionally, transparent huge pages should be disabled. These are enabled by default on many systems, and some of our dependencies require that they be disabled. You can disable them using the following commands:
```
$ sudo su
$ echo never > /sys/kernel/mm/transparent_hugepage/enabled
$ echo never > /sys/kernel/mm/transparent_hugepage/defrag
$ exit
```

Additionally if you'd like to make these changes persist across system restarts then add the following to your `/etc/rc.local` file:
```
if test -f /sys/kernel/mm/transparent_hugepage/enabled; then
   echo never > /sys/kernel/mm/transparent_hugepage/enabled
fi
if test -f /sys/kernel/mm/transparent_hugepage/defrag; then
   echo never > /sys/kernel/mm/transparent_hugepage/defrag
fi
```

After doing the above, install Diventi by running `make install`. It will prompt you to make necessary configurations if needed.