import "pe"

rule KK__33
{
	meta:
		author = "https://github.com/xkucma00/yara-rules.git"
		tool = "TODO 0.1.0"
		description = "TODO"
		hunting_tag = "TODO"
		rule_type = "TODO"
		original_name = "KK"
		original_path = "test1.yar"
		source_id = 4
		id = 33
		predecessor_id = false
		oldest_ancestor_id = false
	condition:
		false
}

rule A__34
{
	meta:
		author = "https://github.com/xkucma00/yara-rules.git"
		tool = "TODO 0.1.0"
		description = "TODO"
		hunting_tag = "TODO"
		rule_type = "TODO"
		original_name = "A"
		original_path = "test1.yar"
		source_id = 4
		id = 34
		predecessor_id = false
		oldest_ancestor_id = false
	condition:
		true or
		false or
		KK__33
}

rule B__35
{
	meta:
		__new_meta = "new"
		author = "https://github.com/xkucma00/yara-rules.git"
		tool = "TODO 0.1.0"
		description = "TODO"
		hunting_tag = "TODO"
		rule_type = "TODO"
		original_name = "B"
		original_path = "test2/tesst.yar"
		source_id = 4
		id = 35
		predecessor_id = false
		oldest_ancestor_id = false
	condition:
		true or
		false or
		pe.number_of_sections != 2 or
		false
}

global rule ahoj__36 : test
{
	meta:
		__also_new = true
		__which = 2
		author = "https://github.com/xkucma00/yara-rules.git"
		tool = "TODO 0.1.0"
		description = "TODO"
		hunting_tag = "TODO"
		rule_type = "TODO"
		original_name = "ahoj"
		original_path = "test2/tesst.yar"
		source_id = 4
		id = 36
		predecessor_id = false
		oldest_ancestor_id = false
	strings:
		$s0 = "water"
	condition:
		$s0 or
		(
			$s0 and
			true
		) or
		A__34 or
		false or
		(
			B__35 and
			false
		)
}

