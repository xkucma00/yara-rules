import "pe"

rule _1
{
	meta:
		author = "https://github.com/xkucma00/yara-rules.git"
		tool = "TODO"
		description = "TODO"
		hunting_tag = "TODO"
		rule_type = "TODO"
		original_name = "KK"
		original_path = "test1.yar"
		source_id = 1
		id = 1
		predecessor_id = false
	condition:
		false
}

rule _2
{
	meta:
		author = "https://github.com/xkucma00/yara-rules.git"
		tool = "TODO"
		description = "TODO"
		hunting_tag = "TODO"
		rule_type = "TODO"
		original_name = "A"
		original_path = "test1.yar"
		source_id = 1
		id = 2
		predecessor_id = false
	condition:
		true or
		false or
		_1
}

rule _3
{
	meta:
		__new_meta = "new"
		author = "https://github.com/xkucma00/yara-rules.git"
		tool = "TODO"
		description = "TODO"
		hunting_tag = "TODO"
		rule_type = "TODO"
		original_name = "B"
		original_path = "test2/tesst.yar"
		source_id = 1
		id = 3
		predecessor_id = false
	condition:
		true or
		false or
		pe.number_of_sections != 2 or
		false
}

global rule _4 : test
{
	meta:
		__also_new = "
"
		__which = "__which"
		author = "https://github.com/xkucma00/yara-rules.git"
		tool = "TODO"
		description = "TODO"
		hunting_tag = "TODO"
		rule_type = "TODO"
		original_name = "ahoj"
		original_path = "test2/tesst.yar"
		source_id = 1
		id = 4
		predecessor_id = false
	strings:
		$s0 = "water"
	condition:
		$s0 or
		(
			$s0 and
			true
		) or
		_2 or
		false or
		(
			_3 and
			false
		)
}

