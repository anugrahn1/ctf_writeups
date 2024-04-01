---
published: false
---
# Notes

## Github
---
```sh
git add <files>
git commit -m "message"
git push origin gh-pages
```

## Jekyll
---
```sh
# See site WITHOUT drafts
jekyll serve
# See site WITH drafts
jekyll serve --draft
```

## Blog Post Header
---
```
---
title: "title"
permalink: "/link"
published: true/false   
---
```
## Markdown

For `c` snippets, make sure the format for codeblocks is `c` and **NOT** `C`. 

Syntax Highlighting `C`:

```C
int main(void){
    printf("Hello, World\n");
    return 0;
}
```

Syntax Highlighting `c`:

```c
int main(void){
    printf("Hello, World\n");
    return 0;
}
```

Although on Github, they might look the same, when I check the website, the `C` doesn't have syntax highlighting.