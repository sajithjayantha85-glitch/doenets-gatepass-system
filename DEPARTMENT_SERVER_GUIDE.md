# 🏛️ ශ්‍රී ලංකා විභාග දෙපාර්තමේන්තුව - අභ්‍යන්තර Server (Local Office Server) හි පද්ධතිය සකස් කිරීමේ සරල මාර්ගෝපදේශය

මෙම උපදෙස් මාලාව අනුගමනය කිරීමෙන්, විභාග දෙපාර්තමේන්තු පරිශ්‍රය තුළ ඇති පරිගණකයක් (Office PC / Server) මූලික Server එක ලෙස භාවිත කර, **ඉන්ටර්නෙට් නොමැතිව වුවද (Offline / Local Network)** ආරක්ෂක ගේට්ටුවේ Wi-Fi ජාලය හරහා QR Gate Pass System එක 100% නොමිලේ ධාවනය කළ හැක.

---

## 🌟 Local Office Server එකක Hosting කිරීමේ ප්‍රධාන වාසි
1. **100% නොමිලේ:** මාසික Hosting ගාස්තු හෝ Cloud වියදම් කිසිවක් නැත.
2. **ඉහළම වේගය (0ms Lag):** Local Wi-Fi / Router ජාලය හරහා ඉතා වේගයෙන් වැඩ කරයි.
3. **Offline ක්‍රියාකාරීත්වය:** ඉන්ටර්නෙට් විසන්ධි වුවද ගේට්ටුවේ පද්ධතිය නොකඩවා වැඩ කරයි.
4. **දත්ත සුරක්ෂිතභාවය:** සියලුම පැමිණීම් සහ සේවක විස්තර දෙපාර්තමේන්තු පරිශ්‍රයෙන් පිටතට නොගොස් Server පරිගණකයේම සුරක්ෂිතව පවතී.

---

## 🛠️ පියවරෙන් පියවර සකස් කරගන්නා ආකාරය (Step-by-Step Setup Guide)

### 📌 පියවර 1: Server පරිගණකයේ Node.js ස්ථාපනය කිරීම
1. [nodejs.org](https://nodejs.org) වෙත ගොස් **Node.js (LTS Version)** Download කර Server පරිගණකයේ Install කරන්න.
2. Install වී ඇත්දැයි බැලීමට Command Prompt (cmd) ඇර `node -v` ලෙස ටයිප් කර Enter කරන්න. (Version අංකය පෙන්වනු ඇත).

---

### 📌 පියවර 2: Project ගොනු (Files) Server පරිගණකයට කොපි කිරීම
1. මෙම `gate pass system` ෆෝල්ඩරය Server පරිගණකයේ සුදුසු ස්ථානයකට Copy කරන්න (උදා: `C:\doenets-gatepass`).
2. Command Prompt එක ඇර එම ෆෝල්ඩරය තුළට යන්න (`cd C:\doenets-gatepass`).
3. පහත විධානය ක්‍රියාත්මක කර අවශ්‍ය Libraries Install කරගන්න:
   ```cmd
   npm install
   ```

---

### 📌 පියවර 3: Server පරිගණකයේ Local IP ලිපිනය සොයාගැනීම
1. Server පරිගණකයේ Command Prompt එකෙහි `ipconfig` ලෙස ටයිප් කර Enter කරන්න.
2. එහි ඇති **IPv4 Address** එක සටහන් කරගන්න (උදා: `192.168.1.100`).
3. *(නිර්දේශය: Server පරිගණකයේ IP එක මාරු නොවන පරිදි Static IP එකක් ලෙස Router එකෙන් සකස් කිරීම වඩාත් සුදුසුය).*

---

### 📌 පියවර 4: පරිගණකය On වන විටම (Windows Boot) ඉබේ Server එක Start වීම
පරිගණකය Off වී On වන විටම, කිසිවෙකු Log නොවී වුවද පද්ධතිය පසුබිමින් (Background) ඉබේම ධාවනය වීමට `PM2` භාවිත කරන්න:

Command Prompt (Administrator ලෙස ඇර) පහත විධානයන් පිළිවෙලින් ක්‍රියාත්මක කරන්න:
```cmd
npm install -g pm2
npm install -g pm2-windows-startup
pm2-startup install
pm2 start server.js --name "gatepass-system"
pm2 save
```

---

### 📌 පියවර 5: Windows Firewall මගින් Port 5000 Allow කිරීම
වෙනත් Phones / Laptops වලට Server එකට සම්බන්ධ වීමට ඉඩදීම සඳහා:
1. Start Menu එකෙහි **"Windows Defender Firewall with Advanced Security"** ලෙස Search කර തുറන්න.
2. වම් පස ඇති **Inbound Rules** ක්ලික් කර දකුණු පස ඇති **New Rule...** තෝරන්න.
3. **Port** තෝරා Next කරන්න -> **TCP** සහ Specific local ports හි `5000` ලෙස සටහන් කර Next කරන්න.
4. **Allow the connection** තෝරා Next කරන්න -> සියල්ල Tick කර Next කරන්න -> Name ලෙස `GatePassPort5000` ලෙස ලබා දී **Finish** කරන්න.

---

### 📌 පියවර 6: පද්ධතිය භාවිත කිරීම (Accessing the System)

ආරක්ෂක නිලධාරීන්ගේ සහ කාර්ය මණ්ඩලයේ Phones / Tablets / Laptops මගින් දෙපාර්තමේන්තු Wi-Fi එකට සම්බන්ධ වී බ්‍රවුසරයෙන් (Chrome / Edge / Safari):

👉 **`http://192.168.1.100:5000`** *(මෙහි `192.168.1.100` යනු ඔබේ Server පරිගණකයේ IP එකයි)*

ලෙස ටයිප් කර පද්ධතිය සෘජුවම භාවිත කළ හැක.

---

### 📌 පියවර 7: දත්ත බැක්අප් ලබාගැනීම (Database Backup)
Super Admin ගිණුමෙන් ලොග් වී Dashboard එකෙහි උඩ ඇති **`📥 Backup DB`** බොත්තම ක්ලික් කිරීමෙන් ඕනෑම වේලාවක සියලුම දත්ත JSON file එකක් ලෙස Download කර සුරක්ෂිතව තබාගත හැක.
