# Apache-Struts-v4

El script contiene 5 vulnerabilidades distintas que explotarn vulnerabilidades de tipo RCE en ApacheStruts. por el momento solo contiene la capacidad de crear shell PHP.
<br>

## SHELL
**php** `Funcion Terminada :)`<br>
<br>

## CVE ADD
|CVE ID| DESC|
|-|-
|CVE-2013-2251|Apache Struts 2.0.0 through 2.3.15 allows remote attackers to execute arbitrary OGNL expressions via a parameter with a crafted (1) action:, (2) redirect:, or (3) redirectAction: prefix.
|CVE-2017-5638|The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.
|CVE-2017-9805|The REST Plugin in Apache Struts 2.1.1 through 2.3.x before 2.3.34 and 2.5.x before 2.5.13 uses an XStreamHandler with an instance of XStream for deserialization without any type filtering, which can lead to Remote Code Execution when deserializing XML payloads.
|CVE-2018-11776|Apache Struts versions 2.3 to 2.3.34 and 2.5 to 2.5.16 suffer from possible Remote Code Execution when alwaysSelectFullNamespace is true (either by user or a plugin like Convention Plugin) and then: results are used with no namespace and in same time, its upper package have no or wildcard namespace and similar to results, same possibility when using url tag which doesn't have value and action set and in same time, its upper package have no or wildcard namespace.
|CVE-2019-0230|Apache Struts 2.0.0 to 2.5.20 forced double OGNL evaluation, when evaluated on raw user input in tag attributes, may lead to remote code execution.

<p align="center">
  <img src="https://github.com/s1kr10s/Apache-Struts-v3/blob/master/screen.png" width="600" alt="accessibility text">
</p>
<br>

## Upload Shell
Esta funcionalidad es efectiva cuando el servidor no tiene conexion a internet de tal manera que no podemos subir un archivo y la mejor opcion seria crear un archivo ya estando dentro.
<br>
<p align="center">
  <img src="https://github.com/s1kr10s/Apache-Struts-v3/blob/master/shell.jpg" width="550" alt="accessibility text">
</p>

Thanks.
