# GO_BUILD_TAGS is the extra build-tag set CI passes to every stage it calls.
GO_BUILD_TAGS ?=

go_tags_empty :=
go_tags_space := $(go_tags_empty) $(go_tags_empty)
go_tags_comma := ,

# go_tags_uniq keeps the first occurrence of each word, in order.
go_tags_uniq = $(if $(1),$(firstword $(1)) $(call go_tags_uniq,$(filter-out $(firstword $(1)),$(1))))
go_tags_words = $(subst $(go_tags_comma),$(go_tags_space),$(1))
go_tags_join = $(subst $(go_tags_space),$(go_tags_comma),$(strip $(call go_tags_uniq,$(call go_tags_words,$(1)) $(call go_tags_words,$(GO_BUILD_TAGS)))))

go_tags = $(if $(strip $(GO_BUILD_TAGS)),$(go_tags_join),$(1))
go_tags_flag = $(if $(strip $(call go_tags,$(1))),$(go_tags_space)-tags=$(call go_tags,$(1)))
