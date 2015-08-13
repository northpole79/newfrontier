module GLOBAL;

## Returns the haversine distance between two IP addresses based on GeoIP
## database locations
##
##
## orig: the address of orig connection
## resp: the address of resp server
## Returns: the GeoIP distance between orig and resp in miles
function haversine_distance_ip(orig: addr, resp: addr): double
{

        local miles: double ;

        local orig_loc = lookup_location(orig);
        local resp_loc = lookup_location(resp);
        miles = haversine_distance(orig_loc$latitude, orig_loc$longitude, resp_loc$latitude, resp_loc$longitude);

        #if (distance == "nan")
        #       return 0 ;

        return miles ;
}
