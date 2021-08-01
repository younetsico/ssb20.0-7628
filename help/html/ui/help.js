if ($("#whtoc").html() == undefined) {
    var encoding = document.charset || document.characterSet || "utf-8";
    encoding = encoding.toLowerCase();
    
    if (encoding.indexOf("jis") > -1) {
        $.ajax({
            beforeSend: function( xhr ) {
                xhr.overrideMimeType( "text/html; charset=Shift_JIS" );
            },
            url: "_toc.htm", success: function (data) {
                $("#whsizer").html(data);
                loadTree();
            }
        });
    } else {
        $.ajax({
           url: "_toc.htm", success: function (data) {
                $("#whsizer").html(data);
                loadTree();
            }
        });
    }
} else {
    loadTree();
}
    
checkForNewVersion(location.href);

function loadTree() {
    
    $("#whtoc").addClass("tree").show();
    $('.tree li:has(ul)').addClass('parent_li').prepend("<span class='ygtvtp'></span>").find(' > span').attr('title', 'Expand this branch');
    $('.tree li:not(.parent_li)').prepend("<span class='ygtvln'></span>");

    selectNodeByHref(location.href);

    if (typeof updateHeight == 'function') updateHeight();

    $('.tree li.parent_li > span').on('click', function (e) {
        var children = $(this).parent('li.parent_li').find(' > ul > li');
        var isExpanded = false;
        if (children.is(":visible")) {
            children.hide();
            $(this).attr('title', 'Expand this branch').addClass('ygtvtp').removeClass('ygtvlm');
        } else {
            isExpanded = true;
            children.show();
            $(this).attr('title', 'Collapse this branch').addClass('ygtvlm').removeClass('ygtvtp');
        }

        var height = $("#whtoc").height();
        $("#resizerCol").css("height", height+"px"); //make the resizerCol's height auto.

        if (isExpanded) {
            if (typeof onHelpTreeExpanded == 'function') onHelpTreeExpanded($(this));
        } else {
            if (typeof onHelpTreeCollapsed == 'function') onHelpTreeCollapsed($(this));
        }
        e.stopPropagation();
    });
}

//Expand the tree nodes according to current href.
function selectNodeByHref(href) {
    if ("/" == href.slice(href.length - 1)) //if root, then select default.htm 
        href += 'default.htm';

    $("#whtoc li").each(function () {
        var h = "/" + $(this).children("a").attr("href");
        if (href.indexOf(h) > -1) {
            $(this).children("a").addClass("current_bold");
            $("#whtoc li.active").removeClass("active");
            $(this).parents("li").addClass("active");
            $(this).parents("ul").each(function () {
                $(this).children('li').show();
                $(this).siblings("span").attr('title', 'Collapse this branch').addClass('ygtvlm').removeClass('ygtvtp');
            });
            $(this).children("ul").children("li").show();
            if ($(this).children("span").hasClass('ygtvtp')) {
                $(this).children("span").attr('title', 'Collapse this branch').addClass('ygtvlm').removeClass('ygtvtp');
            }
            return false;
        }
    });
}

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
        url[url.length-1] = "";
        
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
        var _this = this;
        $("#whleftcol").append("<div id='resizerCol'></div>");
        /* initialize correct position of parent table row */
        _this._setWidth(_this._getAdaptableWidth());
        /*
         *The event start have to be the virtual partition line.
         *But the event end just should be that mouse up in the table.
         * Maybe this just is a virtual "drag" event.
         */
        $("#resizerCol").mousedown(function () {
            treeWidthResizer.isDrag = true;
        });
        $("#whlayout").mouseup(function () {
            treeWidthResizer.isDrag = false;
        });

        $("#whcontent").mousemove(function (e) {
            if(treeWidthResizer.isDrag){
                var left = $("#whcontent").position().left;
                var width = Math.ceil(e.pageX - left);
                if (width < 600 && width > 200) {
                    _this._setWidth(width);
                }
                return false; //prevent to select other text content.
            }
        });
        // resize width when expanding with overflow items
        $(".ygtvtp, .ygtvlm").on("click", function(e){
            _this._setWidth(_this._getAdaptableWidth());
        });

    },
    _setWidth: function(width) {
        $("#whsizer").css("width", width + "px");
        //$("#whheader > h1").css("marginLeft", width + 20 + "px"); //auto-align the title of header
        $("#whleftcol").css("width", width + 10 + "px");
        $("#whleftcol").css("min-width", width + 10 + "px");
        // save position values for future pages in the same session
        sessionStorage.setItem("#whsizer--width", width + "px");
        sessionStorage.setItem("#whleftcol--width", width + 10 + "px");
        sessionStorage.setItem("#whleftcol--min-width", width + 10 + "px");
    },
    _getAdaptableWidth: function() {
        var recorded_width = Number($("#whsizer").css("width").split("px")[0]);
        var mininum_width = Number($("#whsizer")[0].scrollWidth);
        if (recorded_width <= mininum_width) {
            return mininum_width + 10;
        } else {
            return recorded_width;
        }
    }
}
$(function(){
    treeWidthResizer.init();
});


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

/* Set and Get cookie function */
function setCookie(cname, cvalue, exdays) {
  var d = new Date();
  d.setTime(d.getTime() + (exdays * 24 * 60 * 60 * 1000));
  var expires = "expires="+d.toUTCString();
  document.cookie = cname + "=" + cvalue + ";" + expires + ";path=/";
}

function getCookie(cname) {
  var name = cname + "=";
  var ca = document.cookie.split(';');
  for(var i = 0; i < ca.length; i++) {
    var c = ca[i];
    while (c.charAt(0) == ' ') {
      c = c.substring(1);
    }
    if (c.indexOf(name) == 0) {
      return c.substring(name.length, c.length);
    }
  }
  return "";
}

$(document).ready(function () {
    if ($("meta[name='author']").length == 0) return;
    var host = $("meta[name='author']").attr('content');
    var sendto = "support@" + host.replace("www.", "");
    if(host.indexOf("4dpayments") > -1) {
      host = "www.nsoftware.com";
    }
    if(host.indexOf("sftpnetdrive") > -1) {
      host = "www.nsoftware.com";
      sendto = "support@nsoftware.com";
    }    
    var formAction = 'https://' + host + '/kb/help/form.rst?force=true';
    var subject = $("meta[name='generator']").attr('content') || "Help Page:" + document.title;

    //regenerate a bootstrap modals window 
    var modalHtml = "<div class='modal fade' id='questionModal'>" +
      "<div class='modal-dialog' style='width:500px;'>" +
        "<div class='modal-content'>" +
          "<div class='modal-header'>" +
            "<button type='button' class='close' data-dismiss='modal' aria-label='Close'><span aria-hidden='true'>&times;</span></button>" +
            "<h4 class='modal-title'>Questions / Feedback?</h4>" +  //modal title
          "</div>" +
          "<div class='modal-body'>" +
            "<form id='modal_feedbackform' action='" + formAction + "' method='post'>" +
            "<div class='form-group'><label>Name</label><input type=text name='name' value='' class='text form-control'/></div>" +
            "<div class='form-group'><label>Email</label><input type=text name='email' value='' class='text form-control'/></div>" +
            "<label>Feedback</label><textarea class='form-control' rows='3' name='message' placeholder='Please enter questions / feedback ...'></textarea>" +
            "<input type=hidden name=sendto value='" + sendto + "' /><input type=hidden name=subject value='" + subject + "' />" +
            "</form>"+
          "</div>" +
          "<div class='modal-footer'>" +
            "<button type='button' class='btn btn-default' data-dismiss='modal'>Close</button>" +
            "<button type='button' class='btn btn-primary' id='modal-form-submit'>Send Feedback</button>" +
          "</div>" +
        "</div>" +
      "</div>" +
    "</div>";
    $("body").append(modalHtml);

    //show the modal
    $("#whfeedback").bind("click", function () {
        $("#questionModal").modal('show');
    });

    //submit
    $("#modal-form-submit").on("click", function () {
        var message = $("#modal_feedbackform textarea[name='message']").val();
        if (!message) {
            alert("Please enter questions / feedback");
            return false;
        }
        $("#modal_feedbackform").submit();
    });

    $("#whtoc a.static-link").on('click', function(){
      $(this).prev("span").click();
    });

    //Show the syntax content by user's choose
    var helpSyntaxCookieName = "_nsoftware_ononline_help_syntax";
    var checkUserSyntax = function () {
      var syntax = getCookie(helpSyntaxCookieName);
      var syntaxTabs = $("#wrapper ul.syntax-tabs");
      if(syntax && syntaxTabs.get(0)) {
        syntaxTabs.find("li").each(function(){
          if(syntax == $(this).text()) {
            $(this).find("a").trigger("click");
          }
        });
      }
    }();
   
    $("#wrapper ul.syntax-tabs li").on("click", function() {
      setCookie(helpSyntaxCookieName, $(this).text(), 1); //Save the cookie 1 day
    });
});

