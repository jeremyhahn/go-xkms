# GO_BUILD_TAGS is the extra build-tag set ci-template passes to every stage
# it calls: `make lint|build|coverage|security|integration-test
# GO_BUILD_TAGS='a b'` (space separated; go-xkms#1603). Included by the root
# Makefile and by xkey/Makefile, so both join it the same way.
#
# $(call go_tags,TAGS) is the one join every -tags flag goes through. With
# GO_BUILD_TAGS empty or unset it is TAGS exactly as given, so no command line
# changes. Otherwise it is TAGS (space or comma separated) followed by
# GO_BUILD_TAGS, duplicates dropped, as one comma-joined list: go reads a
# -tags value that holds a comma as a comma list, so the two separators are
# never mixed in one value.
#
# $(call go_tags_flag,TAGS) is for a command that passes no -tags of its own
# (gosec, govulncheck): " -tags=<joined>" with its leading space, or nothing
# when the joined list is empty.
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
