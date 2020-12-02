$(function(){
    $('ul.parent > li').hover(function(){
        $(this).find('ul.child').show(400);
    }, function(){
        $(this).find('ul.child').hide(400);
    });
});