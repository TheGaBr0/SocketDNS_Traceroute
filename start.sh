/home/progettoreti/Desktop/progettoreti/./kill.sh

> log.txt

gnome-terminal --title "DNSauth_1" -- bash -c "/home/progettoreti/Desktop/progettoreti/DNS/AUTHORITATIVE/./DNSauth_1" 
xdotool search DNSauth_1 windowminimize
gnome-terminal --title "DNSauth_2" -- bash -c "/home/progettoreti/Desktop/progettoreti/DNS/AUTHORITATIVE/./DNSauth_2" 
xdotool search DNSauth_2 windowminimize
gnome-terminal --title "DNSauth_3" -- bash -c "/home/progettoreti/Desktop/progettoreti/DNS/AUTHORITATIVE/./DNSauth_3 " 
xdotool search DNSauth_3 windowminimize
gnome-terminal --title "DNSauth_4" -- bash -c "/home/progettoreti/Desktop/progettoreti/DNS/AUTHORITATIVE/./DNSauth_4 " 
xdotool search DNSauth_4 windowminimize
gnome-terminal --title "DNStld_1" -- bash -c "/home/progettoreti/Desktop/progettoreti/DNS/TLD/./DNStld_1 "
xdotool search DNStld_1 windowminimize
gnome-terminal --title "DNStld_2" -- bash -c "/home/progettoreti/Desktop/progettoreti/DNS/TLD/./DNStld_2 " 
xdotool search DNStld_2 windowminimize
gnome-terminal --title "DNSroot" -- bash -c "/home/progettoreti/Desktop/progettoreti/DNS/./DNSroot "
xdotool search DNSroot windowminimize
gnome-terminal --title "DNSlocale" -- bash -c "/home/progettoreti/Desktop/progettoreti/DNS/./DNSlocale "
xdotool search DNSlocale windowminimize
gnome-terminal --title "Client" -- bash -c "while true; do sudo /home/progettoreti/Desktop/progettoreti/./Client; sleep 1; done; exec bash"










