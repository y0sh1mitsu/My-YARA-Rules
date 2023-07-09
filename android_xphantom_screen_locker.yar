rule android_xphantom_screen_locker : Android Screen Locker
{
        meta:
                author      = "y0sh1mitsu"
                description = "Detect Android XPhantom Screen Locker (freefollowers.apk - XPhantom)"
                reference   = "https://bazaar.abuse.ch/sample/5251a356421340a45c8dc6d431ef8a8cbca4078a0305a87f4fbd552e9fc0793e"
                hash        = "5251a356421340a45c8dc6d431ef8a8cbca4078a0305a87f4fbd552e9fc0793e"
                version     = "1.0"

        strings:

                $a = "Free Followers"
                $b = "You are Hacked By Anonymous Group"
                $c = "Pay 1000/Rs to Get UnlocK Key on that number +923044466333"


        condition:
        uint32be(0) == 0x504B0304
        and $a
        and $b
        and $c
}
