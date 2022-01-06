<?php
#==============================================================================
# LTB Self Service Password
#
# Copyright (C) 2009 Clement OUDOT
# Copyright (C) 2009 LTB-project.org
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# GPL License: http://www.gnu.org/licenses/gpl.txt
#
#==============================================================================

function ucsapi_escape( $str ) {
    $out = '';
    for ($i=0;$i<strlen($str);$i++) {
            $hex = dechex(ord($str[$i]));
            if ($hex=='')
                    $out = $out.urlencode($str[$i]);
            else
                    $out = $out .'%'.((strlen($hex)==1) ? ('0'.strtoupper($hex)):(strtoupper($hex)));
    }
    $out = str_replace('+','%20',$out);
    $out = str_replace('=','%3D',$out);
    $out = str_replace('_','%5F',$out);
    $out = str_replace(',','%2C',$out);
    $out = str_replace('.','%2E',$out);
    $out = str_replace('-','%2D',$out);
    return $out;
}

function ucsapi_headersToArray( $str ) {
    $headers = array();
    $headersTmpArray = explode( "\r\n" , $str );
    for ( $i = 0 ; $i < count( $headersTmpArray ) ; ++$i ){
            // we dont care about the two \r\n lines at the end of the headers
            if ( strlen( $headersTmpArray[$i] ) > 0 ) {
                    // the headers start with HTTP status codes, which do not contain a colon so we can filter them out too
                    if ( strpos( $headersTmpArray[$i] , ":" ) ) {
                            $headerName = substr( $headersTmpArray[$i] , 0 , strpos( $headersTmpArray[$i] , ":" ) );
                            $headerValue = substr( $headersTmpArray[$i] , strpos( $headersTmpArray[$i] , ":" )+1 );
                            $headers[$headerName] = $headerValue;
                    }
            }
    }
    return $headers;
}

function ucsapi_RESTcall( $method, $url, $user = '', $pass = '', $data = false, $header = false ) {

    $head[] = 'User-Agent: SSP 1.5-ucs-patch';
    $head[] = 'Accept: application/json';
    $head[] = 'Accept-Language: de-DE; q=1.0, en-US; q=0.9';

    if ($data) {
        $head[] = 'Content-Type: application/json';
        $head[] = 'Content-Length: '. strlen($data);
    }

    if (!$header) {
        array_push( $head, $header );
    }

    $curl = curl_init();
    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $method);
    curl_setopt($curl, CURLOPT_HTTPHEADER, $head);
    curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_HEADER, true);

    if ( $user !== '' AND $pass !== '' ) {
        curl_setopt($curl, CURLOPT_USERPWD, $user . ':' . $pass );
    }

    $response = curl_exec( $curl );
    if ($response) {
        $info = curl_getinfo( $curl );
        $result['status'] = $info['http_code'];
        $result['header'] = ucsapi_headersToArray( substr( $response, 0, $info['header_size'] ) );
        $result['body'] = substr( $response, $info['header_size'] );
    } else {
        $result['status'] = 0;
    }

    return $result;

}

function ucsapi_change( $api_url, $api_user, $api_pass, $login, $userdn, $newpassword ) {

    $result = "";

    // request password object
    $url = $api_url . 'users/passwd/' . ucsapi_escape( $userdn );
    $response = ucsapi_RESTcall( 'GET', $url, $api_user, $api_pass );

    if ($response['status'] == 0) {
        $result = "passworderror";
        error_log("UCS API - request password object error");
    } else {
        $body = json_decode( $response['body'], true );
        $passwd_position = $body['position'];
        $passwd_etag = trim( $response['header']['Etag'] );
    }

    // modify password object
    if ($result === '' ) {
        $headers = ('If-Match: ' . $passwd_etag );
        $data = array(
            'uuid' => 'string',
            'uri' => $api_url . 'users/passwd/' . $userdn,
            'position' => $passwd_position,
            'properties' => array(
                'username' => $login,
                'password' => $newpassword
            )
        );
        $data_json = json_encode( $data, JSON_UNESCAPED_SLASHES );
        $response = ucsapi_RESTcall( 'PUT', $url, $api_user, $api_pass, $data_json, $headers );

        if ($response['status'] != 204) {
            $result = "passworderror";
            error_log("UCS API - change password object error");
        } else {
            $result = "passwordchanged";
        }    
    }

    return $result;
}