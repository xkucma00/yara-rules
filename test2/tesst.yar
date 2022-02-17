include "../test1.yar"

rule B {
  condition:
    true or false
}

rule ahoj : test {
  strings:
    $s0 = "water"
  condition:
    $s0 or ($s0 and true)
}
