# paloalto
Yazılım Tanımlı Ağ Güvenlik Yönetimi

Palo Alto güvenlik duvarında tanımlı custom-url-category nesnesine USOM'dan gelen yeni zararlı alanları otomatik olarak ekler.
Güvenlik duvarında "commit" işlemi yapar.

 Kullanim: ./palo-url-guncelleyici.py fw1 <opsiyonel: domain>
 
"Credentials tag" dosyasının oluşturulması için
wget --no-check-certificate "https://<PaloAltoFW_Mng_IP>/esp/restapi.esp?type=keygen&user=<PaloALto_user>&password=<PaloAlto_passwd>" --output-document=pan-key.xml
pan-key.xml dosyasındaki API_KEY_NUMARASI not edilir

panrc dosyası ~ altında oluşturulur.
