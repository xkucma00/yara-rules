
rule KK {
  condition:
    true or false
}

rule A {
  condition:
      true or false or KK
}
