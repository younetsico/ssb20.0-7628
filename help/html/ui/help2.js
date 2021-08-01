/*
 The help2.js and tree2.css just apply to the single page layout
*/
checkForNewVersion(location.href);
function checkForNewVersion(href) {     
  if ($("#newver").length == 0 || href.indexOf("file:///") > -1 || href.indexOf("localhost/") > -1) return;
    try {
        var url = href.split('/');
        prod = url[url.length-3]; //get product
        v = prod.charAt(2);     //find version
        
        var vMap = "123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        var v2 = vMap.charAt(vMap.indexOf(v) + 1);
        var prodChar = prod.split("");
        prodChar[2] = v2;
        prod = prodChar.join("");
        
        url[url.length-3] = prod;
        //url[url.length-1] = "";
        
        href = url.join("/");

        $.ajax({
            url: href, success: function (data) {
                $("#newver").html("<i>A new version of this product is available! </i> [<a href='" + href + "'>learn more</a>]");
            }
        });
    }
    catch(err) { }
}

var treeWidthResizer = {
    isDrag: false,
    x:0,
    init:function(){
        $("#whleftcol").append("<div id='resizerCol' style='margin-left:280px;'></div>");
        /*
         *The event start have to be the virtual partition line.
         *But the event end just should be that mouse up in the table.
         * Maybe this just is a virtual "drag" event.
         */
        $("#resizerCol").mousedown(function () {
            treeWidthResizer.isDrag = true;
        });
        $("#whlayout").mouseup(function (e) {
            if (treeWidthResizer.isDrag) {
                var pageX = e.pageX;
                //$("#whheader > h1").css("marginLeft", (pageX + 20) + "px"); //auto-align the title of header
                $("#whleftcol").css("width", (pageX + 10) + "px");
                $("#resizerCol").css("marginLeft", (pageX-10) + "px");
            }
            treeWidthResizer.isDrag = false;
        });

        $("#whlayout tr:eq(1)").mousemove(function (e) {
          if (treeWidthResizer.isDrag) {
              $("#whsizer").css("width", e.pageX + "px");
          }
          if (treeWidthResizer.isDrag) {
              return false; //prevent to select other text content.
          }
        });

    }
}

treeWidthResizer.init();

//Syntax Highlighting of Code
$('#whiframe pre').each(function (e) {
    if (!$(this).hasClass('syntax')) {
        l = $(this).attr('lang');
        if (l == null || l == '') l = 'csharp';
        if (l == 'none') l = ''; //If "none" then we do not want any highlighting just the formatting. The value "plain" exists but is not exactly the same as nothing.

        var found = false;
        if ($(this).find("div.source").get(0)) {
            found = true;
        }

        if (!found) { //Handle Special Help File Case where syntax highlighting was pre configured          
            $(this).replaceWith("<pre class='brush: "+l+"; gutter:false; wrap-lines: true; auto-links: false; class-name:code'>"+$(this).html()+"</pre>");
        } else {
            $(this).replaceWith("<div>" + $(this).html() + "</div>");
        }
    }
});

SyntaxHighlighter.all();

$(document).ready(function () {
    //scrollto
    function scrollTo(id) {
        if(!$(id).html() && !$("a[name='"+id.substring(1)+"']").html()){
            return ;
        }

        $("#whtoc>ul").removeClass("nav");  //remove scrollspy 
        
        if($("#whtoc li a[href='" + id + "']").text()) {
            $("#whtoc li.active").removeClass("active");
            $("#whtoc li a[href='" + id + "']").parents("li").addClass("active");
            $("#whtoc li.active").each(function () {
                if($(this).is(".parent_li")){
                    expandParentNode(this);
                }
            });
        }
        var isIdObj = ($(id).html() != undefined);
        if((isIdObj && $(id).is("a")) || $("a[name='"+id.substring(1)+"']").html()){
            setTimeout(function(){
                var obj = isIdObj ? id : ("a[name='"+id.substring(1)+"']");
                $("body").scrollTop($(obj).offset().top - 80);
            }, 100);
        }

        //add scrollspy 
        setTimeout(function(){
            $("#whtoc>ul").addClass("nav"); 
            setScrollspy();
        },600);

        /*fix the tree's width for IE*/
        var treeWidth = $("#resizerCol").css("margin-left");
        $("#resizerCol").css("margin-left","0px;");
        $("#resizerCol").css("margin-left",treeWidth);
        treeScrollTop();
    };

    if(location.hash) scrollTo(location.hash);

    $("#whtoc li a").on("click", function () {
        var id = $(this).attr("href");
        scrollTo(id);
    });
  
    //for embedded links in the helpfile content we should scrollto as well
    $("#whcontent a").on("click", function () {
        var id = $(this).attr("href");
        if (id.indexOf("#") > -1) {//only scrollto if link is local to the page
            scrollTo(id);
        }
    });

    //set the left tree's position is fixed
    function setTreeHeight() {
        var viewHeight = document.body.clientHeight;
        var headerHeight = $("#whheader").height();
        $("#whsizer").css({ "position": "fixed"});
        $("#whsizer,#resizerCol").css({ "height": (viewHeight - headerHeight - 5), "min-height": "0" });
    }
    setTreeHeight();

    $(window).resize(function () {
        setTreeHeight();
    });

    function setScrollspy() {
        if($("#whtoc>ul").hasClass("nav")){
            $('body').scrollspy({
                offset: 100,
                target: '#whtoc'
            });
        }
    }
    setScrollspy();

    // if we scroll manually, it should open the tree and highlight the correct section 
    var choke = null;
    $('body').on('activate.bs.scrollspy', function (e) {
        clearTimeout(choke);
        choke = setTimeout(function() {
            //IE issue fixed:if the previous event is the tree expand event, the activate.bs.scrollspy leads to we cannot click the sibling tree node, so skip it
            if (e.isTrigger == 3 && e.namespace == "bs.scrollspy") {
                $("#whtoc li.active").parents(".parent_li").each(function () {
                   expandParentNode(this);
                });
            }
            //treeScrollTop();
        }, 100);
    });
});

