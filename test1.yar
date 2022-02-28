
rule KK {
  condition:
    true
}

rule A {
  condition:
      true or false or KK
}
