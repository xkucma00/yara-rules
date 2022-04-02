
rule KK {
  condition:
    false and true
}

rule A {
  condition:
      true or false or KK or true
}
