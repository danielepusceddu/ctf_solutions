<?php
$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");
$clear = json_encode($defaultdata);
$encrypted = base64_decode("ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw=");

$key = "";
for($i = 0; $i < strlen($encrypted); $i++){
    $key .= $clear[$i] ^ $encrypted[$i];
}

echo("Key: ".$key."\n"); //qw8Jqw8Jqw8J....

function xor_encrypt($key, $in) {
    $text = $in;
    $outText = '';

    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

$mydata = array( "showpassword"=>"yes", "bgcolor"=>"#ffffff");
$mycookie = base64_encode(xor_encrypt("qw8J", json_encode($mydata)));
echo("Cookie: ".$mycookie."\n");
?>
